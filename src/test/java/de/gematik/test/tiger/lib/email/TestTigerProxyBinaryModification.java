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
package de.gematik.test.tiger.lib.email;

import static org.awaitility.Awaitility.await;

import de.gematik.rbellogger.RbelConverter;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.renderer.RbelHtmlRenderer;
import de.gematik.rbellogger.testutil.RbelElementAssertion;
import de.gematik.test.tiger.common.data.config.tigerproxy.DirectReverseProxyInfo;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyModifierDescription;
import de.gematik.test.tiger.proxy.handler.RbelBinaryModifierPlugin;
import java.io.FileWriter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.junit.jupiter.api.Test;

@Slf4j
class TestTigerProxyBinaryModification {

  @SneakyThrows
  @Test
  void modifyPop3Traffic() {
    try (val replayer =
            PcapReplayer.writeReplay(
                """
            S: +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
            C: CAPA
            S: +OK
            S: fdsa
            S: blubsblab
            S: .
            client: RETR 1
            server: +OK body follows
            server: MailBody
            server: .
            client: QUIT
            server: +OK bye
            """);
        val tigerProxy =
            replayer.replayWithDirectForwardUsing(
                new TigerProxyConfiguration()
                    .setDirectReverseProxy(
                        DirectReverseProxyInfo.builder()
                            .modifierPlugins(
                                List.of(
                                    TigerProxyModifierDescription.builder()
                                        .name("MyBinaryModifier")
                                        .parameters(
                                            Map.of(
                                                "targetString",
                                                "1896.697170952@dbc.mtview.ca.us",
                                                "replacementString",
                                                "my.modified_43243434343@message_sss"))
                                        .build(),
                                    TigerProxyModifierDescription.builder()
                                        .name("MyBinaryModifier")
                                        .parameters(
                                            Map.of(
                                                "targetString",
                                                "RETR 1",
                                                "replacementString",
                                                "retr 22"))
                                        .build()))
                            .build())
                    .setActivateRbelParsingFor(List.of("pop3", "mime"))); ) {

      new RbelHtmlRenderer()
          .doRender(
              tigerProxy.getRbelMessagesList(), new FileWriter("target/pcapReplayerPop.html"));
      await()
          .atMost(5, TimeUnit.SECONDS)
          .until(() -> tigerProxy.getMessages().size() >= 7);

      try {
        RbelElementAssertion.assertThat(tigerProxy.getMessageHistory().getFirst())
            .andPrintTree()
            .asString()
            .contains("my.modified_43243434343@message_sss");
        RbelElementAssertion.assertThat(tigerProxy.getRbelMessagesList().get(3))
            .andPrintTree()
            .extractChildWithPath("$.pop3Arguments")
            .hasStringContentEqualTo("22");
      } catch (AssertionError e) {
        tigerProxy.getMessages().stream()
            .map(RbelElement::printTreeStructure)
            .forEach(log::info);

        replayer.getReceivedPacketsInServer().stream()
            .map(String::new)
            .map("Server: "::concat)
            .forEach(log::info);
        replayer.getReceivedPacketsInClient().stream()
            .map(String::new)
            .map("Client: "::concat)
            .forEach(log::info);
      }
    }
  }

  @Data
  public static class MyBinaryModifier implements RbelBinaryModifierPlugin {
    private String targetString;
    private String replacementString;

    @Override
    public Optional<byte[]> modify(RbelElement target, RbelConverter converter) {
      if (target.getRawStringContent().contains(targetString)) {
        final String newContent =
            target.getRawStringContent().replace(targetString, replacementString);
        log.info("Modifying content from {} to {}", target.getRawStringContent(), newContent);
        return Optional.of(newContent.getBytes());
      } else {
        return Optional.empty();
      }
    }

    public String toString() {
      return "MyBinaryModifier{"
          + "targetString='"
          + targetString
          + '\''
          + ", replacementString='"
          + replacementString
          + '\''
          + '}';
    }
  }
}
