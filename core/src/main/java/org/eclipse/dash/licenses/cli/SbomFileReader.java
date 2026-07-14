package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.Parser;
import org.cyclonedx.parsers.XmlParser;
import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.PackageUrlIdParser;
import org.eclipse.dash.licenses.spdx.SpdxDependencyFileReader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

public class SbomFileReader implements IDependencyListReader {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
	private static final PackageUrlIdParser PURL_PARSER = new PackageUrlIdParser();

	private final File file;

	public SbomFileReader(File file) throws FileNotFoundException {
		if (!file.exists()) {
			throw new FileNotFoundException(file.getPath());
		}
		this.file = file;
	}

	@Override
	public Collection<IContentId> getContentIds() {
		SbomFormat format = detectFormat(file);

		switch (format) {
		case CYCLONEDX_JSON:
			return parseCycloneDxJson(file);
		case CYCLONEDX_XML:
			return parseCycloneDxXml(file);
		case CYCLONEDX_YAML:
			return parseCycloneDxYaml(file);
		case SPDX_JSON:
		case SPDX_TAG_VALUE:
		case SPDX_YAML:
		case SPDX_RDF_XML:
		case SPDX_XML:
		case SPDX_XLS:
			return new SpdxDependencyFileReader(file).getContentIds();
		case UNKNOWN:
		default:
			throw new RuntimeException("Unsupported SBOM format for file: " + file.getPath());
		}
	}

	private SbomFormat detectFormat(File file) {
		String name = file.getName().toLowerCase();

		if (name.endsWith(".json")) {
			return detectJsonFormat(file);
		}
		if (name.endsWith(".rdf") || name.endsWith(".rdf.xml")) {
			return SbomFormat.SPDX_RDF_XML;
		}
		if (name.endsWith(".spdx") || name.endsWith(".txt")) {
			return SbomFormat.SPDX_TAG_VALUE;
		}
		if (name.endsWith(".yaml") || name.endsWith(".yml")) {
			return detectYamlFormat(file);
		}
		if (name.endsWith(".xls") || name.endsWith(".xlsx")) {
			return SbomFormat.SPDX_XLS;
		}
		if (name.endsWith(".xml")) {
			return isSpdxXml(file) ? SbomFormat.SPDX_XML : SbomFormat.CYCLONEDX_XML;
		}

		return SbomFormat.UNKNOWN;
	}

	private SbomFormat detectJsonFormat(File file) {
		try {
			JsonNode root = OBJECT_MAPPER.readTree(file);
			if (root.has("spdxVersion")) {
				return SbomFormat.SPDX_JSON;
			}
			return SbomFormat.CYCLONEDX_JSON;
		} catch (IOException e) {
			return SbomFormat.UNKNOWN;
		}
	}

	private SbomFormat detectYamlFormat(File file) {
		try {
			JsonNode root = YAML_MAPPER.readTree(file);
			if (root.has("spdxVersion")) {
				return SbomFormat.SPDX_YAML;
			}
			return SbomFormat.CYCLONEDX_YAML;
		} catch (IOException e) {
			return SbomFormat.UNKNOWN;
		}
	}

	private boolean isSpdxXml(File file) {
		try {
			String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
			return content.contains("<spdxVersion>") || content.contains("SpdxDocument")
					|| content.contains("spdx:spdxVersion");
		} catch (IOException e) {
			return false;
		}
	}

	private List<IContentId> parseCycloneDxJson(File file) {
		return parseCycloneDx(file, new JsonParser());
	}

	private List<IContentId> parseCycloneDxXml(File file) {
		return parseCycloneDx(file, new XmlParser());
	}

	private List<IContentId> parseCycloneDx(File file, Parser parser) {
		try {
			var sbom = parser.parse(file);
			List<IContentId> results = new ArrayList<>();

			if (sbom.getMetadata() != null && sbom.getMetadata().getComponent() != null) {
				IContentId id = PURL_PARSER.parseId(sbom.getMetadata().getComponent().getPurl());
				if (id != null) {
					results.add(id);
				}
			}
			if (sbom.getComponents() != null) {
				for (var component : sbom.getComponents()) {
					IContentId id = PURL_PARSER.parseId(component.getPurl());
					if (id != null) {
						results.add(id);
					}
				}
			}

			return results;
		} catch (ParseException e) {
			return new ArrayList<>();
		}
	}

	private List<IContentId> parseCycloneDxYaml(File file) {
		try {
			JsonNode root = YAML_MAPPER.readTree(file);
			List<IContentId> results = new ArrayList<>();
			for (JsonNode component : root.path("components")) {
				IContentId id = PURL_PARSER.parseId(component.path("purl").asText(null));
				if (id != null) {
					results.add(id);
				}
			}
			return results;
		} catch (IOException e) {
			return new ArrayList<>();
		}
	}

	private enum SbomFormat {
		CYCLONEDX_XML, CYCLONEDX_JSON, CYCLONEDX_YAML, SPDX_JSON, SPDX_TAG_VALUE, SPDX_YAML, SPDX_RDF_XML, SPDX_XML,
		SPDX_XLS, UNKNOWN
	}
}
