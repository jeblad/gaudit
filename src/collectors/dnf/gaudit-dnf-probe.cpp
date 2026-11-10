// SPDX-License-Identifier: GPL-3.0-only
// gaudit-dnf-probe: collector for the Fedora package rows on Home.
//
// Uses libdnf5 with the metadata already in the system cache (cache only,
// never the network). Without arguments it prints one S-expression:
//
//   (dnf (installed N) (upgradable N) (extras N) (above N))
//
//   installed   installed packages
//   upgradable  name.arch pairs an upgrade would update (excludes and
//               versionlock are applied by libdnf5, like dnf itself)
//   extras      installed packages no enabled repository offers ("dnf list
//               --extras"), leaving out install-only packages such as old
//               kernels, which are kept on purpose
//   above       installed packages a repository offers only in a lower
//               version, so no update reaches them (install-only left out)
//
// With "list" it prints those packages (extras and above), one per line,
// then their count:
//
//   (package (name "...") (arch "...") (version "...") (group G) (offered "..."))
//   (end (count N))
//
// G is gaudit_sourceless_group: 0 above the source (offered is the highest
// version a repository has), 1 offered nowhere and from the distribution
// (vendor "Fedora Project": probably left over from an older release),
// 2 offered nowhere and from someone else.
//
// Written in C++ because libdnf5 has only a C++ API; it is a separate
// process, so only the S-expression crosses to gAudit. Exit status 127
// (the dynamic loader failing) means a library is missing; any other
// failure exits with 1 and prints nothing.
#include <libdnf5/base/base.hpp>
#include <libdnf5/repo/repo_sack.hpp>
#include <libdnf5/rpm/package_query.hpp>

#include <libdnf5/rpm/nevra.hpp>

#include <cstdio>
#include <cstring>
#include <exception>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

// Printable ASCII only, quotes and backslashes escaped; anything else
// fails the run rather than being passed on.
bool quote(const std::string & in, std::string & out)
{
    out = "\"";
    for (char c : in) {
        if (c < 0x20 || c > 0x7e)
            return false;
        if (c == '"' || c == '\\')
            out += '\\';
        out += c;
    }
    out += '"';
    return true;
}

std::string evr(const libdnf5::rpm::Package & p)
{
    std::string e = p.get_epoch();
    std::string vr = p.get_version() + "-" + p.get_release();
    return e.empty() || e == "0" ? vr : e + ":" + vr;
}

struct Entry {
    std::string name, arch, version, offered;
    int group;
};

}  // namespace

int main(int argc, char * argv[])
{
    bool list = argc == 2 && std::strcmp(argv[1], "list") == 0;
    if (argc > 2 || (argc == 2 && !list))
        return 1;
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

        std::vector<Entry> entries;
        for (const auto & pkg : extras)
            entries.push_back({ pkg.get_name(), pkg.get_arch(), evr(pkg), "",
                                pkg.get_vendor() == "Fedora Project" ? 1 : 2 });

        // Above the source: offered by name.arch, but only in lower versions.
        libdnf5::rpm::PackageQuery available(base);
        available.filter_available();
        std::map<std::string, libdnf5::rpm::Package> best;
        for (const auto & pkg : available) {
            std::string key = pkg.get_name() + "." + pkg.get_arch();
            auto it = best.find(key);
            if (it == best.end())
                best.emplace(key, pkg);
            else if (libdnf5::rpm::evrcmp(pkg, it->second) > 0)
                it->second = pkg;
        }
        libdnf5::rpm::PackageQuery offered(installed);
        offered.difference(extras);
        offered.difference(installonly);
        size_t above = 0;
        for (const auto & pkg : offered) {
            auto it = best.find(pkg.get_name() + "." + pkg.get_arch());
            if (it == best.end() || libdnf5::rpm::evrcmp(pkg, it->second) <= 0)
                continue;
            above++;
            entries.push_back({ pkg.get_name(), pkg.get_arch(), evr(pkg), evr(it->second), 0 });
        }

        if (!list) {
            std::printf("(dnf (installed %zu) (upgradable %zu) (extras %zu) (above %zu))\n",
                        installed.size(), upgradable.size(), extras.size(), above);
            return std::fflush(stdout) == 0 ? 0 : 1;
        }
        for (const auto & e : entries) {
            std::string name, arch, version, from;
            if (!quote(e.name, name) || !quote(e.arch, arch) || !quote(e.version, version)
                || !quote(e.offered, from))
                return 1;
            std::printf("(package (name %s) (arch %s) (version %s) (group %d) (offered %s))\n",
                        name.c_str(), arch.c_str(), version.c_str(), e.group, from.c_str());
        }
        std::printf("(end (count %zu))\n", entries.size());
        return std::fflush(stdout) == 0 ? 0 : 1;
    } catch (const std::exception &) {
        return 1;
    } catch (...) {
        return 1;
    }
}
