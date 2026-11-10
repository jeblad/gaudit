// SPDX-License-Identifier: GPL-3.0-only
// gaudit-dnf-probe: collector for the Fedora package rows on Home.
//
// Uses libdnf5 with the metadata already in the system cache (cache only,
// never the network) and prints one S-expression on stdout:
//
//   (dnf (installed N) (upgradable N) (extras N))
//
//   installed   installed packages
//   upgradable  name.arch pairs an upgrade would update (excludes and
//               versionlock are applied by libdnf5, like dnf itself)
//   extras      installed packages no enabled repository offers ("dnf list
//               --extras"), leaving out install-only packages such as old
//               kernels, which are kept on purpose
//
// Written in C++ because libdnf5 has only a C++ API; it is a separate
// process, so only the S-expression crosses to gAudit. Exit status 127
// (the dynamic loader failing) means a library is missing; any other
// failure exits with 1 and prints nothing.
#include <libdnf5/base/base.hpp>
#include <libdnf5/repo/repo_sack.hpp>
#include <libdnf5/rpm/package_query.hpp>

#include <cstdio>
#include <exception>
#include <set>
#include <string>

int main()
{
    try {
        libdnf5::Base base;
        base.load_config();

        auto & config = base.get_config();
        // Read what is cached; never download. As an ordinary user, read
        // the system cache instead of the user's own (usually empty) one.
        config.get_cacheonly_option().set(libdnf5::Option::Priority::RUNTIME, "all");
        config.get_cachedir_option().set(libdnf5::Option::Priority::RUNTIME,
                                         config.get_system_cachedir_option().get_value());
        base.setup();

        auto repo_sack = base.get_repo_sack();
        repo_sack->create_repos_from_system_configuration();
        repo_sack->load_repos();

        libdnf5::rpm::PackageQuery installed(base);
        installed.filter_installed();

        libdnf5::rpm::PackageQuery upgrades(base);
        upgrades.filter_upgrades();
        upgrades.filter_latest_evr();
        std::set<std::string> upgradable;
        for (const auto & pkg : upgrades)
            upgradable.insert(pkg.get_name() + "." + pkg.get_arch());

        libdnf5::rpm::PackageQuery installonly(base);
        installonly.filter_installed();
        installonly.filter_provides(config.get_installonlypkgs_option().get_value());

        libdnf5::rpm::PackageQuery extras(base);
        extras.filter_extras();
        extras.difference(installonly);

        std::printf("(dnf (installed %zu) (upgradable %zu) (extras %zu))\n",
                    installed.size(), upgradable.size(), extras.size());
        return std::fflush(stdout) == 0 ? 0 : 1;
    } catch (const std::exception &) {
        return 1;
    } catch (...) {
        return 1;
    }
}
