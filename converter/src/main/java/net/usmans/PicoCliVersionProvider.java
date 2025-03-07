// Copyright 2025, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package net.usmans;

import picocli.CommandLine;

public class PicoCliVersionProvider implements CommandLine.IVersionProvider {
  @Override
  public String[] getVersion() throws Exception {
    return new String[] {PicoCliVersionProvider.class.getPackage().getImplementationVersion()};
  }
}
