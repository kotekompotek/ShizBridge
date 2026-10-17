package bridge.shizbridge.app.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CodeGenTest {

    @Test
    fun codeLengthAndAlphabet() {
        repeat(100) {
            val code = CodeGen.generate()
            assertEquals(CodeGen.LENGTH, code.length)
            assertTrue(code.all { it in CodeGen.ALPHABET })
            assertTrue(code.none { it in "ILOU" })
        }
    }

    @Test
    fun codesAreNotRepeated() {
        val seen = mutableSetOf<String>()
        repeat(500) { seen.add(CodeGen.generate()) }
        assertEquals(500, seen.size)
        assertNotEquals(CodeGen.generate(), CodeGen.generate()) // astronomically unlikely
    }

    @Test
    fun normalizeFixesConfusables() {
        assertEquals("0111", CodeGen.normalize("o1il"))
        assertEquals("0000", CodeGen.normalize("OOOO"))
        assertEquals(CodeGen.generate().length, CodeGen.normalize(CodeGen.generate().lowercase()).length)
    }
}
