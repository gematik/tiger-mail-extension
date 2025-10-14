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

import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerTlsConfiguration;
import de.gematik.test.tiger.proxy.TigerProxy;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;

@Slf4j
public abstract class AbstractTigerProxyTest {

  public TigerProxy tigerProxy;


  @BeforeEach
  public void logTestName(TestInfo testInfo) {
    log.info(
        "Now executing test '{}' ({}:{})",
        testInfo.getDisplayName(),
        testInfo.getTestClass().map(Class::getName).orElse("<>"),
        testInfo.getTestMethod().map(Method::getName).orElse("<>"));
  }

  @AfterEach
  public void stopSpawnedTigerProxy() {
    shouldServerRun.set(false);
    if (tigerProxy != null) {
      log.info("Closing tigerProxy from '{}'...", this.getClass().getSimpleName());
      tigerProxy.close();
    }
  }

  public void spawnTigerProxyWithDefaultRoutesAndWith(TigerProxyConfiguration configuration) {
    spawnTigerProxyWith(configuration);
  }

  public void spawnTigerProxyWith(TigerProxyConfiguration configuration) {
    configuration.setProxyLogLevel("ERROR");
    configuration.setName("Primary Tiger Proxy");
    if (configuration.getTls() == null) {
      configuration.setTls(new TigerTlsConfiguration());
    }
    if (StringUtils.isEmpty(configuration.getTls().getMasterSecretsFile())) {
      configuration.getTls().setMasterSecretsFile("target/master-secrets.txt");
    }
    tigerProxy = new TigerProxy(configuration);
  }

  AtomicBoolean shouldServerRun = new AtomicBoolean(true);



}
