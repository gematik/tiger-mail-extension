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
package de.gematik.rbellogger.converter;

import de.gematik.rbellogger.RbelConverter;
import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.configuration.RbelConfiguration;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.RbelMessageMetadata;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import de.gematik.rbellogger.util.RbelContent;
import de.gematik.rbellogger.util.RbelSocketAddress;
import org.junit.jupiter.api.BeforeEach;

class AbstractResponseConverterTest {
  protected RbelConverter converter;

  @BeforeEach
  void init() {
    converter =
        RbelLogger.build(
                new RbelConfiguration().activateConversionFor("pop3").activateConversionFor("mime"))
            .getRbelConverter();
  }

  RbelElement convertMessagePair(String request, String response) {
    var sender = RbelSocketAddress.create("host1", 1);
    var receiver = RbelSocketAddress.create("host2", 2);
    convertToRbelElement(request, sender, receiver);
    return convertToRbelElement(response, receiver, sender);
  }

  RbelElement convertToRbelElement(String request) {
    var sender = RbelSocketAddress.create("host1", 1);
    var receiver = RbelSocketAddress.create("host2", 2);
    return convertToRbelElement(request, sender, receiver);
  }

  RbelElement convertToRbelElement(String input, RbelSocketAddress sender, RbelSocketAddress recipient) {
    return converter.parseMessage(
        input.getBytes(StandardCharsets.UTF_8),
        new RbelMessageMetadata().withSender(sender).withReceiver(recipient));
  }

  /**
   * Live traffic arrives as a content that is made of many small parts (the chunks of the
   * connection), not as one array.
   */
  static RbelContent inPartsOf(int partSize, String input) {
    byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
    var parts = new ArrayList<RbelContent>();
    for (int from = 0; from < bytes.length; from += partSize) {
      parts.add(RbelContent.of(java.util.Arrays.copyOfRange(bytes, from, Math.min(bytes.length, from + partSize))));
    }
    return RbelContent.concat(parts);
  }

  RbelElement convertToRbelElement(RbelContent input) {
    var sender = RbelSocketAddress.create("host1", 1);
    var receiver = RbelSocketAddress.create("host2", 2);
    return converter.parseMessage(
        RbelElement.builder().content(input).build(),
        new RbelMessageMetadata().withSender(sender).withReceiver(receiver));
  }
}
