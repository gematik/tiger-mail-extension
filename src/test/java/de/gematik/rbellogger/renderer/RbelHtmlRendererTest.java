/*
 *
 * Copyright 2021-2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */
package de.gematik.rbellogger.renderer;

import static de.gematik.rbellogger.TestUtils.readCurlFromFileWithCorrectedLineBreaks;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.rbellogger.RbelConverter;
import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.configuration.RbelConfiguration;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.RbelMessageMetadata;
import de.gematik.rbellogger.data.core.RbelBinaryFacet;
import de.gematik.rbellogger.data.core.RbelNoteFacet;
import de.gematik.rbellogger.data.core.RbelTcpIpMessageFacet;
import de.gematik.rbellogger.facets.timing.RbelMessageTimingFacet;
import de.gematik.rbellogger.util.RbelSocketAddress;
import de.gematik.rbellogger.util.RbelValueShader;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RbelHtmlRendererTest {

  private static final RbelConverter RBEL_CONVERTER =
      RbelLogger.build(
              new RbelConfiguration()
                  .activateConversionFor("pop3")
                  .activateConversionFor("mime"))
          .getRbelConverter();
  private static final RbelHtmlRenderer RENDERER = new RbelHtmlRenderer();

  @BeforeEach
  void resetConfig() {
    TigerGlobalConfiguration.reset();
  }

  @ParameterizedTest
  @ValueSource(strings = {"CAPA", "RETR 1"})
  void shouldRenderPop3Messages(String command) throws IOException {
    String pop3Message = command + "\r\n";
    byte[] htmlBytes = pop3Message.getBytes(StandardCharsets.UTF_8);
    final RbelElement convertedMessage =
        RBEL_CONVERTER.parseMessage(
            htmlBytes,
            new RbelMessageMetadata()
                .withSender(RbelSocketAddress.create("sender", 13421))
                .withReceiver(RbelSocketAddress.create("receiver", 14512))
                .withTransmissionTime(ZonedDateTime.now()));

    final String convertedHtml = RENDERER.render(List.of(convertedMessage));
    FileUtils.writeStringToFile(new File("target/directHtml.html"), convertedHtml);

    String[] commandline = command.split(" ");
    assertThat(convertedHtml)
        .contains("POP3 Request")
        .contains("Command: </b>" + commandline[0])
        .contains("Arguments: </b>" + (commandline.length > 1 ? commandline[1] : ""));
  }

  @ParameterizedTest
  @ValueSource(strings = {"+OK foobar foobar", "-ERR barfoo"})
  void shouldRenderPop3Responses(String response) {
    String pop3Message = response + "\r\nbody\r\n.\r\n";
    byte[] htmlBytes = pop3Message.getBytes(StandardCharsets.UTF_8);
    final RbelElement convertedMessage =
        RBEL_CONVERTER.parseMessage(
            htmlBytes,
            new RbelMessageMetadata()
                .withSender(RbelSocketAddress.create("sender", 13421))
                .withReceiver(RbelSocketAddress.create("receiver", 14512))
                .withTransmissionTime(ZonedDateTime.now()));

    final String convertedHtml = RENDERER.render(List.of(convertedMessage));

    String firstline = response.split("\r\n")[0];
    String[] responseLine = firstline.split(" ");
    assertThat(convertedHtml)
        .contains("POP3 Response")
        .contains("Status: </b>" + responseLine[0])
        .contains("Header: </b>" + (responseLine.length > 1 ? responseLine[1] : ""));
  }
}
