package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.PackageUrlIdParser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SbomFileReader implements IDependencyListReader {

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
            case SPDX_JSON:
                return parseSpdxJson(file);
            case SPDX_TAG_VALUE:
                return parseSpdxTagValue(file);
            case CYCLONEDX_YAML:
            case SPDX_YAML:
            case SPDX_RDF_XML:
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
        if (name.endsWith(".xml")) {
            return SbomFormat.CYCLONEDX_XML;
        }
        if (name.endsWith(".spdx") || name.endsWith(".txt")) {
            return SbomFormat.SPDX_TAG_VALUE;
        }
        if (name.endsWith(".yaml") || name.endsWith(".yml")) {
            return SbomFormat.CYCLONEDX_YAML;
        }
        return SbomFormat.UNKNOWN;
    }

    // Distinguishes CycloneDX JSON ("bomFormat" field) from SPDX JSON ("spdxVersion" field).
    private SbomFormat detectJsonFormat(File file) {
        try {
            JsonNode root = new ObjectMapper().readTree(file);
            if (root.has("spdxVersion")) {
                return SbomFormat.SPDX_JSON;
            }
            return SbomFormat.CYCLONEDX_JSON;
        } catch (IOException e) {
            return SbomFormat.UNKNOWN;
        }
    }

   private List<IContentId> parseCycloneDxJson(File file) {

        var parser = new JsonParser();
        try {
            var sbom = parser.parse(file);
            //return sbom.getDependencies().stream().map(each->new PackageUrlIdParser().parseId(each.getRef())).collect(Collectors.toList());
            List<IContentId> results = new ArrayList<>();
            for (var each : sbom.getDependencies()) {
                results.add(new PackageUrlIdParser().parseId(each.getRef()));
            }
            return results;
        }
        catch (ParseException e) {
            e.printStackTrace();
        }

        return new ArrayList<>();
    }

    private List<IContentId> parseCycloneDxXml(File file) {
        var parser = new XmlParser();
        try {
            var sbom = parser.parse(file);
            return sbom.getDependencies().stream().map(each -> new PackageUrlIdParser().parseId(each.getRef())).collect(Collectors.toList());
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final PackageUrlIdParser PURL_PARSER = new PackageUrlIdParser();

    private List<IContentId> parseSpdxJson(File file) {
        try {
            JsonNode root = OBJECT_MAPPER.readTree(file);
            List<IContentId> results = new ArrayList<>();

            for (JsonNode pkg : root.path("packages")) {
                for (JsonNode ref : pkg.path("externalRefs")) {
                    String category = ref.path("referenceCategory").asText("");
                    String type = ref.path("referenceType").asText("");

                    // SPDX 2.2 uses "PACKAGE-MANAGER"; SPDX 2.3 uses "PACKAGE_MANAGER" — accept both
                    if ((category.equalsIgnoreCase("PACKAGE-MANAGER") || category.equalsIgnoreCase("PACKAGE_MANAGER"))
                            && type.equalsIgnoreCase("purl")) {

                        // referenceLocator holds the actual purl string, e.g. "pkg:maven..."
                        String purl = ref.path("referenceLocator").asText(null);

                        if (purl != null) {
                            // Convert the raw purl string into a structured IContentId
                            IContentId id = PURL_PARSER.parseId(purl);

                            // parseId can return null for malformed/unsupported purls — skip those
                            if (id != null) results.add(id);
                        }
                    }
                }
            }
            return results;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    private List<IContentId> parseSpdxTagValue(File file) {
        try {
            List<IContentId> results = new ArrayList<>();

            for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
                // Only process ExternalRef lines — skip everything else (metadata, relationships, etc.)
                if (!line.startsWith("ExternalRef:")) continue;

                // Strip the "ExternalRef:" prefix and split into max. 3 tokens
                String[] parts = line.substring("ExternalRef:".length()).trim().split("\\s+", 3);

                // Validate we have exactly 3 tokens, the right category (2.2 and 2.3 variants), and purl type
                if (parts.length == 3
                        && (parts[0].equalsIgnoreCase("PACKAGE-MANAGER") || parts[0].equalsIgnoreCase("PACKAGE_MANAGER"))
                        && parts[1].equalsIgnoreCase("purl")) {

                    // parts[2] is the purl locator — parse it into a structured IContentId
                    IContentId id = PURL_PARSER.parseId(parts[2]);

                    // parseId can return null for malformed/unsupported purls — skip those
                    if (id != null) results.add(id);
                }
            }
            return results;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    private enum SbomFormat {
        CYCLONEDX_XML,
        CYCLONEDX_JSON,
        CYCLONEDX_YAML,
        SPDX_JSON,
        SPDX_TAG_VALUE,
        SPDX_YAML,
        SPDX_RDF_XML,
        UNKNOWN
    }
}
