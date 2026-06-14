package org.eclipse.dash.licenses.tests.util;

import static org.junit.jupiter.api.Assertions.*;
import org.eclipse.dash.licenses.cli.SbomFileReader;
import java.io.File;
import java.util.Collection;

import org.eclipse.dash.licenses.IContentId;
import org.junit.jupiter.api.Test;

class SbomFileReaderRdfTest {

    @Test
    void testParseSpdxRdfXml() throws Exception {
        File file = new File(getClass().getClassLoader().getResource("test.spdx.rdf").getFile());
        SbomFileReader reader = new SbomFileReader(file);

        Collection<IContentId> ids = reader.getContentIds();

        assertNotNull(ids);
        assertFalse(ids.isEmpty(), "Expected at least one content ID");

        IContentId id = ids.iterator().next();
        assertEquals("maven", id.getType());
        assertEquals("org.apache.commons", id.getNamespace());
        assertEquals("commons-lang3", id.getName());
        assertEquals("3.12.0", id.getVersion());
    }

    @Test
    void testParseSpdxRdfXml_skipsNonPurl() throws Exception {
        // Verifies that non-purl externalRefs are ignored
        File file = new File(getClass().getClassLoader().getResource("test.spdx.rdf").getFile());
        SbomFileReader reader = new SbomFileReader(file);

        Collection<IContentId> ids = reader.getContentIds();

        // Only the purl ref should be returned, not any other ref types
        assertEquals(1, ids.size());
    }

    @Test
    void testParseSpdxRdfXml_fileNotFound() {
        assertThrows(java.io.FileNotFoundException.class, () -> {
            new SbomFileReader(new File("nonexistent.rdf"));
        });
    }
}