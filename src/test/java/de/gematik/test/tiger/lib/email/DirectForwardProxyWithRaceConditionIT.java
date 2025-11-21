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

import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.RbelElementAssertion;
import de.gematik.rbellogger.data.core.TracingMessagePairFacet;
import de.gematik.rbellogger.facets.pop3.RbelPop3Command;
import de.gematik.rbellogger.facets.pop3.RbelPop3CommandFacet;
import de.gematik.rbellogger.facets.pop3.RbelPop3ResponseFacet;
import de.gematik.rbellogger.facets.smtp.RbelSmtpCommandFacet;
import de.gematik.rbellogger.facets.smtp.RbelSmtpResponseFacet;
import de.gematik.rbellogger.renderer.RbelHtmlRenderer;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.proxy.TigerProxy;
import lombok.SneakyThrows;
import lombok.val;
import org.awaitility.Awaitility;
import org.awaitility.core.ConditionTimeoutException;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static de.gematik.test.tiger.lib.email.PcapReplayer.client;
import static de.gematik.test.tiger.lib.email.PcapReplayer.server;
import static org.assertj.core.api.Assertions.assertThat;

public class DirectForwardProxyWithRaceConditionIT {
  public static final String SMTP_COMMUNICATION =
      """
            S: 220 smtp.example.com ESMTP Postfix

            C: HELO relay.example.org

            S: 250 Hello relay.example.org, I am glad to meet you

            C: MAIL FROM:<bob@example.org>

            S: 250 Ok

            C: RCPT TO:<alice@example.com>

            S: 250 Ok

            C: RCPT TO:<theboss@example.com>

            S: 250 Ok

            C: DATA

            S: 354 End data with <CR><LF>.<CR><LF>

            C: From: "Bob Example" <bob@example.org>
            C: To: "Alice Example" <alice@example.com>
            C: Cc: theboss@example.com
            C: Date: Tue, 15 Jan 2008 16:02:43 -0500
            C: Subject: Test message
            C:
            C: Hello Alice.
            C: This is a test message with 5 header fields and 4 lines in the message body.
            C: Your friend,
            C: Bob
            C: .

            S: 250 Ok: queued as 12345

            C: QUIT

            S: 221 Bye
            """;
  public static final String POP3_COMMUNICATION =
      """
            S: +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
            C: AUTH PLAIN
            S: +\s
            C: dGVzdAB0ZXN0AHRlc3Q=
            S: +OK Maildrop locked and ready
            C: AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=
            S: +OK Maildrop locked and ready
            """;

  @SneakyThrows
  @Test
  public void pop3_capaSplitsServerReadyMessage() {
    val replayer =
        PcapReplayer.writeReplay(
            List.of(
                server("+OK POP3 server re"),
                client("CAPA\r\n"),
                server("ady <1896.697170952@dbc.mtview.ca.us>\r\n"),
                server("+OK\r\n"),
                server("UIDL\r\n"),
                server("blubsblab\r\n"),
                server(".\r\n")));
    val tigerProxy =
        replayer.replayWithDirectForwardUsing(
            new TigerProxyConfiguration().setActivateRbelParsingFor(List.of("pop3", "mime")));

    final String html = RbelHtmlRenderer.render(tigerProxy.getRbelMessagesList());
    Files.write(new File("target/pop3Replay.html").toPath(), html.getBytes());
    Awaitility.await()
        .atMost(5, TimeUnit.SECONDS)
            .until(() ->
            tigerProxy.getRbelMessagesList().stream()
                .filter(DirectForwardProxyWithRaceConditionIT::isPop3Message).count() == 3);
  }

  @SneakyThrows
  @Test
  public void pop3_capaPrecedesServerReadyMessage() {
    val replayer =
        PcapReplayer.writeReplay(
            List.of(
                client("CAPA\r\n"),
                server("+OK POP3 server re"),
                server("ady <1896.697170952@dbc.mtview.ca.us>\r\n"),
                server("+OK\r\n"),
                server("UIDL\r\n"),
                server("blubsblab\r\n"),
                server(".\r\n")));
    val tigerProxy =
        replayer.replayWithDirectForwardUsing(
            new TigerProxyConfiguration().setActivateRbelParsingFor(List.of("pop3", "mime")));

    waitForMessages(tigerProxy, 3);

    final String html = RbelHtmlRenderer.render(tigerProxy.getRbelMessagesList());
    Files.write(new File("target/pop3Replay.html").toPath(), html.getBytes());

    Awaitility.await()
        .atMost(5, TimeUnit.SECONDS)
        .until(() ->
            tigerProxy.getRbelMessagesList().stream()
                .filter(DirectForwardProxyWithRaceConditionIT::isPop3Message).count() == 3);
  }

  @SneakyThrows
  @Test
  public void pop3_quitOvertakesRetrResponse() {
    val replayer =
        PcapReplayer.writeReplay(
            List.of(
                server("+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n"),
                client("retr 1\r\n"),
                client("QUIT\r\n"),
                server("+OK body follows\r\n"),
                server("MailBody\r\n"),
                server(".\r\n"),
                server("+OK bye\r\n")));
    val tigerProxy =
        replayer.replayWithDirectForwardUsing(
            new TigerProxyConfiguration().setActivateRbelParsingFor(List.of("pop3", "mime")));

    final String html = RbelHtmlRenderer.render(tigerProxy.getRbelMessagesList());
    Files.write(new File("target/pop3Replay.html").toPath(), html.getBytes());

    waitForMessages(tigerProxy, 5);

    var messages =
        tigerProxy.getRbelMessagesList().stream()
            .filter(DirectForwardProxyWithRaceConditionIT::isPop3Message)
            .toList();
    assertThat(messages).hasSize(5);

    RbelElement retrCommand = messages.get(1);
    RbelElementAssertion.assertThat(retrCommand)
        .extractChildWithPath("$.pop3Command")
        .hasValueEqualTo(RbelPop3Command.RETR);
    RbelElement quitCommand = messages.get(2);
    RbelElementAssertion.assertThat(quitCommand)
        .extractChildWithPath("$.pop3Command")
        .hasValueEqualTo(RbelPop3Command.QUIT);
    RbelElement retrResponse = messages.get(3);
    RbelElementAssertion.assertThat(
            retrResponse.getFacetOrFail(TracingMessagePairFacet.class).getRequest())
        .isEqualTo(retrCommand);
    RbelElement quitResponse = messages.get(4);
    RbelElementAssertion.assertThat(
            quitResponse.getFacetOrFail(TracingMessagePairFacet.class).getRequest())
        .isEqualTo(quitCommand);
  }

  private static boolean isPop3Message(RbelElement msg) {
    return msg.hasFacet(RbelPop3CommandFacet.class) || msg.hasFacet(RbelPop3ResponseFacet.class);
  }

  @SneakyThrows
  @Test
  public void textBlobDemonstratorTest() {
    val replayer = PcapReplayer.writeReplay(SMTP_COMMUNICATION);
    val tigerProxy =
        replayer.replayWithDirectForwardUsing(
            new TigerProxyConfiguration().setActivateRbelParsingFor(List.of("smtp", "mime")));

    waitForMessages(tigerProxy, 14);

    final String html = RbelHtmlRenderer.render(tigerProxy.getRbelMessagesList());
    Files.write(new File("target/mailReplay.html").toPath(), html.getBytes());
    Awaitility.await()
        .atMost(5, TimeUnit.SECONDS)
        .until(() ->
            tigerProxy.getRbelMessagesList().stream()
                .filter(
                    msg ->
                        msg.hasFacet(RbelSmtpCommandFacet.class)
                            || msg.hasFacet(RbelSmtpResponseFacet.class)).count() == 14);
  }

  @SneakyThrows
  @Test
  public void testSmtpRequestPairing() {
    val replayer = PcapReplayer.writeReplay(SMTP_COMMUNICATION);
    val tigerProxy =
        replayer.replayWithDirectForwardUsing(
            new TigerProxyConfiguration().setActivateRbelParsingFor(List.of("smtp")));

    assertThat(
            tigerProxy.getRbelMessagesList().stream()
                .filter(msg -> msg.hasFacet(RbelSmtpCommandFacet.class))
                .allMatch(msg -> msg.hasFacet(TracingMessagePairFacet.class)))
        .isTrue();
  }

  @SneakyThrows
  @Test
  public void testMultilinePop3AuthPlain() {
    val replayer = PcapReplayer.writeReplay(POP3_COMMUNICATION);
    val tigerProxy =
        replayer.replayWithDirectForwardUsing(
            new TigerProxyConfiguration().setActivateRbelParsingFor(List.of("pop3")));

    final String html = RbelHtmlRenderer.render(tigerProxy.getRbelMessagesList());
    Files.write(new File("target/pop3.html").toPath(), html.getBytes());
    Awaitility.await()
        .atMost(5, TimeUnit.SECONDS)
        .until(() ->
            tigerProxy.getRbelMessagesList().stream()
                .filter(DirectForwardProxyWithRaceConditionIT::isPop3Message).count() == 5);
  }



  private static void waitForMessages(TigerProxy tigerProxy, int expectedMessages) {
    try {
      Awaitility.await()
          .atMost(2, TimeUnit.SECONDS)
          .until(() -> tigerProxy.getRbelMessagesList().size(), i -> i == expectedMessages);
    } catch (ConditionTimeoutException ex) {
      tigerProxy.getRbelMessagesList().stream()
          .map(RbelElement::printTreeStructure)
          .forEach(System.out::println);
      throw ex;
    }
  }
}
