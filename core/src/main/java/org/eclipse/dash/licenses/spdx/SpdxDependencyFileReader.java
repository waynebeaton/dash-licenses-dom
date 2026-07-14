/*************************************************************************
 * Copyright (c) 2026 The Eclipse Foundation and others.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution, and is available at https://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 *************************************************************************/
package org.eclipse.dash.licenses.spdx;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.poi.EncryptedDocumentException;
import org.apache.poi.ss.usermodel.DataFormatter;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.PackageUrlIdParser;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.ExternalRef;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxDocument;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.enumerations.ReferenceCategory;
import org.spdx.tools.SpdxToolsHelper;
import org.spdx.tools.SpdxToolsHelper.SerFileType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

public class SpdxDependencyFileReader {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
	private static final PackageUrlIdParser PURL_PARSER = new PackageUrlIdParser();
	private static final Pattern PURL_PATTERN = Pattern.compile("pkg:[^\\s\"'<>]+");
	private static final DataFormatter CELL_FORMATTER = new DataFormatter();
	private static final AtomicBoolean SPDX_TOOLS_INITIALIZED = new AtomicBoolean();

	private final File file;

	public SpdxDependencyFileReader(File file) throws FileNotFoundException {
		if (!file.exists()) {
			throw new FileNotFoundException(file.getPath());
		}
		this.file = file;
	}

	public Collection<IContentId> getContentIds() {
		switch (detectFormat(file)) {
		case JSON:
			return parseJson(file);
		case YAML:
			return parseYaml(file);
		case TAG_VALUE:
			return parseTagValue(file);
		case RDF_XML:
			return parseRdfXml(file);
		case XML:
			return parseXml(file);
		case XLS:
			return parseSpreadsheet(file);
		default:
			throw new RuntimeException("Unsupported SPDX format for file: " + file.getPath());
		}
	}

	private Format detectFormat(File file) {
		String name = file.getName().toLowerCase();

		if (name.endsWith(".rdf") || name.endsWith(".rdf.xml")) {
			return Format.RDF_XML;
		}
		if (name.endsWith(".spdx") || name.endsWith(".tag") || name.endsWith(".txt")) {
			return Format.TAG_VALUE;
		}
		if (name.endsWith(".json")) {
			return Format.JSON;
		}
		if (name.endsWith(".yaml") || name.endsWith(".yml")) {
			return Format.YAML;
		}
		if (name.endsWith(".xls") || name.endsWith(".xlsx")) {
			return Format.XLS;
		}
		if (name.endsWith(".xml")) {
			return Format.XML;
		}
		return Format.UNKNOWN;
	}

	private List<IContentId> parseJson(File file) {
		return parseWithToolsJava(file, SerFileType.JSON);
	}

	private List<IContentId> parseYaml(File file) {
		return parseWithToolsJava(file, SerFileType.YAML);
	}

	private List<IContentId> parseTagValue(File file) {
		try {
			Set<IContentId> found = new LinkedHashSet<>();
			for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
				if (!line.startsWith("ExternalRef:")) {
					continue;
				}

				String[] parts = line.substring("ExternalRef:".length()).trim().split("\\s+", 3);
				if (parts.length != 3 || !isPackageManagerPurl(parts[0], parts[1])) {
					continue;
				}

				IContentId id = PURL_PARSER.parseId(parts[2]);
				if (id != null) {
					found.add(id);
				}
			}
			return new ArrayList<>(found);
		} catch (IOException e) {
			return new ArrayList<>();
		}
	}

	private List<IContentId> parseXml(File file) {
		Set<IContentId> found = new LinkedHashSet<>();
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
			factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

			Document document = factory.newDocumentBuilder().parse(file);
			NodeList elements = document.getElementsByTagNameNS("*", "externalRef");

			for (int i = 0; i < elements.getLength(); i++) {
				Node node = elements.item(i);
				if (node.getNodeType() != Node.ELEMENT_NODE) {
					continue;
				}
				Element externalRef = (Element) node;

				String category = childText(externalRef, "referenceCategory");
				String type = childText(externalRef, "referenceType");
				if (!isPackageManagerPurl(category, type)) {
					continue;
				}

				IContentId id = PURL_PARSER.parseId(childText(externalRef, "referenceLocator"));
				if (id != null) {
					found.add(id);
				}
			}
		} catch (IOException | ParserConfigurationException | SAXException e) {
			return new ArrayList<>();
		}

		return new ArrayList<>(found);
	}

	private String childText(Element parent, String localName) {
		NodeList values = parent.getElementsByTagNameNS("*", localName);
		if (values.getLength() == 0) {
			return "";
		}
		return values.item(0).getTextContent();
	}

	private List<IContentId> parseRdfXml(File file) {
		return parseWithToolsJava(file, SerFileType.RDFXML);
	}

	@SuppressWarnings("unchecked")
	private List<IContentId> parseWithToolsJava(File file, SerFileType fileType) {
		File normalized = file;
		Set<IContentId> found = new LinkedHashSet<>();
		try {
			initializeSpdxTools();
			normalized = normalizeForToolsJava(file, fileType);
			SpdxDocument document = SpdxToolsHelper.deserializeDocumentCompatV2(normalized, fileType);
			List<SpdxPackage> packages = (List<SpdxPackage>) SpdxModelFactory
					.getSpdxObjects(document.getModelStore(), null, SpdxConstantsCompatV2.CLASS_SPDX_PACKAGE,
							document.getDocumentUri(), null)
					.collect(Collectors.toList());
			for (SpdxPackage spdxPackage : packages) {
				addPackageExternalRefs(found, spdxPackage);
			}
		} catch (IOException | InvalidSPDXAnalysisException e) {
			return new ArrayList<>();
		} finally {
			if (!file.equals(normalized)) {
				try {
					Files.deleteIfExists(normalized.toPath());
				} catch (IOException e) {
				}
			}
		}
		return new ArrayList<>(found);
	}

	private void addPackageExternalRefs(Set<IContentId> found, SpdxPackage spdxPackage)
			throws InvalidSPDXAnalysisException {
		for (ExternalRef ref : spdxPackage.getExternalRefs()) {
			String refTypeUri = ref.getReferenceType().getIndividualURI();
			if (ref.getReferenceCategory() != ReferenceCategory.PACKAGE_MANAGER) {
				continue;
			}
			if (!(SpdxConstantsCompatV2.SPDX_LISTED_REFERENCE_TYPES_PREFIX + "purl").equalsIgnoreCase(refTypeUri)
					&& !"purl".equalsIgnoreCase(ref.getReferenceType().toString())) {
				continue;
			}

			IContentId id = PURL_PARSER.parseId(ref.getReferenceLocator());
			if (id != null) {
				found.add(id);
			}
		}
	}

	private void initializeSpdxTools() {
		if (SPDX_TOOLS_INITIALIZED.compareAndSet(false, true)) {
			SpdxToolsHelper.initialize();
		}
	}

	private File normalizeForToolsJava(File file, SerFileType fileType) throws IOException {
		switch (fileType) {
		case JSON:
			return writeNormalizedJsonOrYaml(file, OBJECT_MAPPER, ".json");
		case YAML:
			return writeNormalizedJsonOrYaml(file, YAML_MAPPER, ".yaml");
		default:
			return file;
		}
	}

	private File writeNormalizedJsonOrYaml(File file, ObjectMapper mapper, String suffix) throws IOException {
		JsonNode root = mapper.readTree(file);
		if (!(root instanceof ObjectNode)) {
			return file;
		}
		ObjectNode object = (ObjectNode) root;
		if (object.hasNonNull("documentNamespace")) {
			return file;
		}
		object.put("documentNamespace", syntheticDocumentNamespace(file));
		Path normalized = Files.createTempFile("spdx-tools-", suffix);
		mapper.writeValue(normalized.toFile(), object);
		return normalized.toFile();
	}

	private String syntheticDocumentNamespace(File file) {
		return "https://example.org/spdx/" + file.getName().replaceAll("[^A-Za-z0-9._-]", "-");
	}

	private List<IContentId> parseSpreadsheet(File file) {
		Set<IContentId> found = new LinkedHashSet<>();
		try (var workbook = WorkbookFactory.create(file, null, true)) {
			for (var sheet : workbook) {
				for (var row : sheet) {
					for (var cell : row) {
						Matcher matcher = PURL_PATTERN.matcher(CELL_FORMATTER.formatCellValue(cell));
						while (matcher.find()) {
							IContentId id = PURL_PARSER.parseId(matcher.group());
							if (id != null) {
								found.add(id);
							}
						}
					}
				}
			}
		} catch (IOException | EncryptedDocumentException e) {
			return new ArrayList<>();
		}

		return new ArrayList<>(found);
	}

	private boolean isPackageManagerPurl(String category, String type) {
		return (category.equalsIgnoreCase("PACKAGE-MANAGER") || category.equalsIgnoreCase("PACKAGE_MANAGER"))
				&& type.equalsIgnoreCase("purl");
	}

	private enum Format {
		XML, RDF_XML, TAG_VALUE, JSON, YAML, XLS, UNKNOWN
	}
}
