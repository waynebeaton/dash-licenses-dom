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
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.poi.ss.usermodel.DataFormatter;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.PackageUrlIdParser;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.ExternalRef;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.enumerations.ReferenceCategory;
import org.spdx.spdxRdfStore.RdfStore;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

public class SpdxDependencyFileReader {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
	private static final PackageUrlIdParser PURL_PARSER = new PackageUrlIdParser();
	private static final Pattern PURL_PATTERN = Pattern.compile("pkg:[^\\s\"'<>]+");
	private static final DataFormatter CELL_FORMATTER = new DataFormatter();

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
		try {
			return extractFromSpdxNode(OBJECT_MAPPER.readTree(file));
		} catch (IOException e) {
			return new ArrayList<>();
		}
	}

	private List<IContentId> parseYaml(File file) {
		try {
			return extractFromSpdxNode(YAML_MAPPER.readTree(file));
		} catch (IOException e) {
			return new ArrayList<>();
		}
	}

	private List<IContentId> extractFromSpdxNode(JsonNode root) {
		Set<IContentId> found = new LinkedHashSet<>();

		for (JsonNode pkg : root.path("packages")) {
			for (JsonNode ref : pkg.path("externalRefs")) {
				String category = ref.path("referenceCategory").asText("");
				String type = ref.path("referenceType").asText("");
				if (!isPackageManagerPurl(category, type)) {
					continue;
				}

				IContentId id = PURL_PARSER.parseId(ref.path("referenceLocator").asText(null));
				if (id != null) {
					found.add(id);
				}
			}
		}

		return new ArrayList<>(found);
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
		} catch (Exception e) {
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

	@SuppressWarnings("unchecked")
	private List<IContentId> parseRdfXml(File file) {
		Set<IContentId> found = new LinkedHashSet<>();
		try {
			RdfStore rdfStore = new RdfStore();
			String documentUri = rdfStore.loadModelFromFile(file.getPath(), false);
			List<SpdxPackage> packages = (List<SpdxPackage>) SpdxModelFactory
					.getSpdxObjects(rdfStore, null, SpdxConstantsCompatV2.CLASS_SPDX_PACKAGE, documentUri, null)
					.collect(Collectors.toList());

			for (SpdxPackage spdxPackage : packages) {
				for (ExternalRef ref : spdxPackage.getExternalRefs()) {
					String refTypeUri = ref.getReferenceType().getIndividualURI();
					if (ref.getReferenceCategory() != ReferenceCategory.PACKAGE_MANAGER) {
						continue;
					}
					if (!(SpdxConstantsCompatV2.SPDX_LISTED_REFERENCE_TYPES_PREFIX + "purl")
							.equalsIgnoreCase(refTypeUri)) {
						continue;
					}

					IContentId id = PURL_PARSER.parseId(ref.getReferenceLocator());
					if (id != null) {
						found.add(id);
					}
				}
			}
		} catch (Exception e) {
			return new ArrayList<>();
		}

		return new ArrayList<>(found);
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
		} catch (Exception e) {
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
