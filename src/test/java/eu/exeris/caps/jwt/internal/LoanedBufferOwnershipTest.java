package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.memory.LoanedBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("production code owns no buffer implementation")
class LoanedBufferOwnershipTest {

    private static Path classesRoot() throws URISyntaxException {
        return Path.of(ProblemResponses.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    @Test
    @DisplayName("no compiled production class is a LoanedBuffer")
    void noCompiledLoanedBuffer() throws Exception {
        Path root = classesRoot();
        List<String> offenders;
        try (Stream<Path> files = Files.walk(root)) {
            offenders = files.filter(p -> p.toString().endsWith(".class"))
                    .map(p -> root.relativize(p).toString().replace('/', '.').replaceAll("\\.class$", ""))
                    .filter(name -> !name.equals("module-info"))
                    .filter(name -> {
                        try {
                            return LoanedBuffer.class.isAssignableFrom(Class.forName(name, false,
                                    ProblemResponses.class.getClassLoader()));
                        } catch (ClassNotFoundException | LinkageError e) {
                            return false;
                        }
                    })
                    .toList();
        }
        assertThat(offenders).isEmpty();
    }

    @Test
    @DisplayName("no production source implements LoanedBuffer or extends AbstractLoanedBuffer")
    void noSourceImplementation() throws IOException {
        Path src = Path.of("src/main/java");
        List<String> offenders;
        try (Stream<Path> files = Files.walk(src)) {
            offenders = files.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> {
                        try {
                            String text = Files.readString(p);
                            return text.matches("(?s).*\\b(implements|extends)\\b[^{;]*\\b(Abstract)?LoanedBuffer\\b.*");
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        }
                    })
                    .map(Path::toString)
                    .toList();
        }
        assertThat(offenders).isEmpty();
        assertThat(src.resolve("eu/exeris/caps/jwt/internal/HeapLoanedBuffer.java")).doesNotExist();
    }
}
