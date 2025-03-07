// Copyright 2025, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package net.usmans;

import picocli.CommandLine;

public class PicoCliVersionProvider implements CommandLine.IVersionProvider {
  @Override
  public String[] getVersion() {
    var implementationVersion =
        PicoCliVersionProvider.class.getPackage().getImplementationVersion();
    implementationVersion = implementationVersion == null ? "unknown" : implementationVersion;
    return new String[] {implementationVersion};
  }
}
