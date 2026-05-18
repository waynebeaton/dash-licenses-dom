package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.dash.licenses.ContentId;
import org.eclipse.dash.licenses.IContentId;

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
        try {
            List<Dependency> dependencies = parseDependencies();

            return dependencies.stream()
                .map(this::toContentId)
                .collect(Collectors.toList());
        }
        catch (Exception e) {
            throw new RuntimeException("Unable to parse SBOM file: " + file.getPath(), e);
        }
    }

    private List<Dependency> parseDependencies() throws Exception {
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
            
            // Later: inspect file contents to distinguish CycloneDX JSON vs SPDX JSON.
            return SbomFormat.CYCLONEDX_JSON;
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

   private List<Dependency> parseCycloneDxJson(File file) {
        List<Dependency> dependencies = new ArrayList<>();

        dependencies.add(new Dependency(
            "example-package",
            "1.0.0",
            null
        ));

        return dependencies;
    }

    private List<Dependency> parseCycloneDxXml(File file) {
        // TODO:
        // Same idea as CycloneDX JSON parser, but a CycloneDX XML parser.
        return new ArrayList<>(); 
    }

    private List<Dependency> parseSpdxJson(File file) {
        // TODO:
        // 1. Read an SPDX JSON file.
        // 2. Find the packages array.
        // 3. Extract the name, versionInfo, and purl.
        // 4. Return Dependency objects.
        return new ArrayList<>();
    }

    private List<Dependency> parseSpdxTagValue(File file) {
        // TODO:
        // 1. Read SPDX Tag-Value file 
        // 2. Detect PackageName, PackageVersion, ExternalRef.
        // 3. Return Dependency objects.
        return new ArrayList<>();
    }

    private IContentId toContentId(Dependency dependency) {
        if (dependency.purl != null) {
            IContentId contentId = ContentId.getContentId(dependency.purl);

            if (contentId != null) {
                return contentId;
            }
        }

        return ContentId.getContentId(
            "sbom",
            "sbom",
            "-",
            dependency.name,
            dependency.version
        );
    }

    private static class Dependency {
        final String name;
        final String version;
        final String purl;

        Dependency(String name, String version, String purl) {
            this.name = name;
            this.version = version;
            this.purl = purl;
        }
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