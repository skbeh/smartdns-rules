import argparse
import asyncio
from abc import ABC, abstractmethod
from enum import IntEnum, auto, unique
from functools import reduce
from io import TextIOWrapper
from itertools import groupby, repeat
from sys import stdout
from typing import Final, Iterable, Optional, cast

import aiohttp
from more_itertools import consume, flatten
from validators.domain import domain as domain_validator
from validators.ip_address import ipv4 as ipv4_validator
from validators.ip_address import ipv6 as ipv6_validator
from validators.url import url as url_validator

from pytrie import Trie


@unique
class RuleFormat(IntEnum):
    HOSTS = auto()
    DNSMASQ = auto()
    SMARTDNS = auto()


@unique
class RuleApplication(IntEnum):
    BLOCK = auto()
    BLOCK_IGNORE = auto()
    REDIRECT = auto()
    REDIRECT_IGNORE = auto()
    RESOLVE = auto()


Rule = tuple[RuleApplication, str, Optional[str]]
PlainRule = tuple[str, Optional[str]]
SplittedRule = tuple[RuleApplication, tuple[str, ...], Optional[str]]
SplittedPlainRule = tuple[tuple[str, ...], Optional[str]]


class RuleSet(ABC):
    link: str
    text: list[str]
    rule_set: set[Rule] | set[SplittedRule]

    def __init__(self, link: str) -> None:
        assert url_validator(link)
        self.link = link

    def strip_text(self) -> None:
        def isusable(text: str) -> bool:
            if not text:
                return False
            match text[0]:
                case "#" | "$" | "@":
                    return False
                case _:
                    if "localhost" in text or "loopback" in text:
                        return False
                    return True

        self.text = list(
            filter(
                isusable, map(lambda text: text.replace("\t", " ").strip(), self.text)
            )
        )

    @staticmethod
    @abstractmethod
    def split_single_syntax(raw_rule_line: str) -> Optional[Rule]:
        raise NotImplementedError

    def split_syntax(self) -> None:
        self.rule_set = set(filter(None, map(self.split_single_syntax, self.text)))

    def split_domain(self) -> None:
        def split_single_domain(plain_domain: str) -> Optional[tuple[str, ...]]:
            domain = (
                plain_domain.split("#", maxsplit=1)[0]
                .strip()
                .removeprefix(".")
                .removesuffix(".")
            )
            return tuple(domain.split(".")) if domain_validator(domain) else None

        self.rule_set = set(
            cast(
                Iterable[tuple[RuleApplication, tuple[str, ...], Optional[str]]],
                filter(
                    lambda rule_tuple: rule_tuple[1] is not None,
                    map(
                        lambda rule_tuple: (
                            rule_tuple[0],
                            split_single_domain(rule_tuple[1]),
                            rule_tuple[2],
                        ),
                        cast(set[Rule], self.rule_set),
                    ),
                ),
            )
        )


class SmartDNSRule(RuleSet):
    @staticmethod
    def split_single_syntax(raw_rule_line: str) -> Optional[Rule]:
        rule_line = list(
            filter(
                None,
                flatten(
                    map(
                        lambda rule_line: rule_line.split("/", maxsplit=2),
                        raw_rule_line.split(" ", maxsplit=1),
                    )
                ),
            )
        )
        assert len(rule_line) == 3
        application, domain, destination = rule_line

        if application == "address":
            match destination:
                case "#" | "0.0.0.0" | "127.0.0.1":
                    return (RuleApplication.BLOCK, domain, None)
                case "-":
                    return (RuleApplication.BLOCK_IGNORE, domain, None)
                case _:
                    if ipv4_validator(destination) or ipv6_validator(destination):
                        return (RuleApplication.REDIRECT, domain, destination)
                    assert False

        if application == "nameserver":
            if (
                domain_validator(destination)
                or ipv4_validator(destination)
                or (
                    destination[0] == "["
                    and destination[-1] == "]"
                    and ipv6_validator(destination[1:-1])
                )
            ):
                return (RuleApplication.RESOLVE, domain, destination)

            if destination == "-":
                return (RuleApplication.REDIRECT_IGNORE, domain, None)

            assert False

        assert False


class DnsmasqRule(RuleSet):
    @staticmethod
    def split_single_syntax(raw_rule_line: str) -> Optional[Rule]:
        rule_line = list(
            filter(
                None,
                flatten(
                    map(
                        lambda rule_line: rule_line.split("/", maxsplit=2),
                        raw_rule_line.split("=", maxsplit=1),
                    )
                ),
            )
        )

        if len(rule_line) == 2:
            application, domain = rule_line
            assert application == "address"
            destination = None
        elif len(rule_line) == 3:
            application, domain, destination = rule_line
        else:
            assert False, rule_line

        match application:
            case "address":
                match destination:
                    case None | "0.0.0.0" | "127.0.0.1":
                        return (RuleApplication.BLOCK, domain, None)
                    case _:
                        if ipv4_validator(destination) or ipv6_validator(destination):
                            return (RuleApplication.REDIRECT, domain, destination)
                        assert False

            case "server":
                match destination:
                    case "127.0.0.1#5353":
                        return None
                    case _:
                        return (RuleApplication.REDIRECT, domain, destination)

            case "nameserver":
                return None

            case _:
                assert False


class HostsRule(RuleSet):
    @staticmethod
    def split_single_syntax(raw_rule_line: str) -> Optional[Rule]:
        rule_line = raw_rule_line.split(" ", maxsplit=1)
        assert len(rule_line) == 2
        destination, domain = rule_line

        match destination:
            case "0.0.0.0" | "127.0.0.1" | "::" | "::1":
                return (RuleApplication.BLOCK, domain, None)
            case "255.255.255.255":
                return None
            case _:
                if ipv4_validator(destination) or ipv6_validator(destination):
                    return (RuleApplication.REDIRECT, domain, destination)
                return None


class DomainListRule(RuleSet):
    application: RuleApplication
    destination: Optional[str]

    def __init__(
        self, link: str, application: RuleApplication, destination: Optional[str] = None
    ) -> None:
        super().__init__(link)
        self.application = application
        self.destination = destination

    @staticmethod
    def split_single_syntax(raw_rule_line: str) -> Optional[Rule]:
        raise NotImplementedError

    def split_syntax(self) -> None:
        self.rule_set = set(
            filter(
                None,
                map(
                    lambda rule_line: (self.application, rule_line, self.destination),
                    self.text,
                ),
            )
        )


class SpecifiedHostsRule(DomainListRule):
    def split_syntax(self) -> None:
        self.text = list(
            map(
                lambda text_line: text_line.removeprefix("0.0.0.0")
                .removeprefix("127.0.0.1")
                .strip(),
                self.text,
            )
        )
        super().split_syntax()


RULE_LINK_TUPLE: Final[tuple[RuleSet, ...]] = (
    SmartDNSRule(
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-smartdns.conf"
    ),
    DomainListRule(
        "https://raw.githubusercontent.com/justdomains/blocklists/master/lists/adguarddns-justdomains.txt",
        RuleApplication.BLOCK,
    ),
    DomainListRule(
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext",
        RuleApplication.BLOCK,
    ),
    DomainListRule(
        "https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easylist-justdomains.txt",
        RuleApplication.BLOCK,
    ),
    DomainListRule(
        "https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easyprivacy-justdomains.txt",
        RuleApplication.BLOCK,
    ),
    HostsRule("https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt"),
    HostsRule("https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts"),
    HostsRule("https://adaway.org/hosts.txt"),
    HostsRule("https://someonewhocares.org/hosts/hosts"),
    HostsRule(
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
    ),
    HostsRule(
        "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt"
    ),
    DomainListRule(
        "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestdomains.txt",
        RuleApplication.BLOCK,
    ),
    DomainListRule(
        "https://cokebar.github.io/gfwlist2dnsmasq/gfwlist_domain.txt",
        RuleApplication.RESOLVE,
        "secure",
    ),
    SpecifiedHostsRule(
        "https://raw.githubusercontent.com/vokins/yhosts/master/data/site/down.txt",
        RuleApplication.BLOCK_IGNORE,
    ),
)


def encode_smartdns(
    block_rule_list: Optional[list[SplittedPlainRule]],
    redirect_rule_list: Optional[list[SplittedPlainRule]],
    resolve_rule_list: Optional[list[SplittedPlainRule]],
) -> list[str]:
    def join_domain(rule_list: list[SplittedPlainRule]) -> list[PlainRule]:
        return list(map(lambda rule: (".".join(rule[0]), rule[1]), rule_list))

    config_list: list[str] = []

    if block_rule_list is not None:
        config_list += list(
            map(lambda rule: f"address /{rule[0]}/#", join_domain(block_rule_list))
        )

    if redirect_rule_list is not None:
        config_list += list(
            map(
                lambda rule: f"address /{rule[0]}/{rule[1]}",
                join_domain(redirect_rule_list),
            )
        )

    if resolve_rule_list is not None:
        config_list += list(
            map(
                lambda rule: f"nameserver /{rule[0]}/{rule[1]}",
                join_domain(resolve_rule_list),
            )
        )

    return config_list


def output(outfile: TextIOWrapper) -> None:
    def extract_set(
        application: RuleApplication,
        rule_set_list: list[tuple[RuleApplication, set[SplittedPlainRule]]],
    ) -> Optional[set[SplittedPlainRule]]:
        filtered_list = list(
            filter(
                lambda rule_set_tuple: rule_set_tuple[0] == application, rule_set_list
            )
        )
        if len(filtered_list) == 1:
            return filtered_list[0][1]
        if len(filtered_list) == 0:
            return None
        assert False, filtered_list

    def remove_included(rule_set: set[SplittedPlainRule]) -> None:
        local_rule_list = list(map(lambda rule: tuple(reversed(rule[0])), rule_set))
        trie = Trie.fromkeys(local_rule_list)

        for domain in local_rule_list:
            covered_plain_domain_set: set[tuple[str]] = set(
                map(
                    lambda domain_tuple: tuple(reversed(domain_tuple[0])),
                    trie.iter_prefix_items(domain),
                )
            )
            try:
                covered_plain_domain_set.remove(tuple(reversed(domain)))
            except KeyError:
                pass
            if next(iter(rule_set))[1] is None:
                covered_domain_set = set(
                    map(lambda domain: (domain, None), covered_plain_domain_set)
                )
                covered_domain_set.intersection_update(rule_set)
                rule_set -= covered_domain_set

    def remove_ignore(
        rule_set: set[SplittedPlainRule], ignore_rule_set: set[SplittedPlainRule]
    ) -> None:
        # local_rule_set = rule_set.copy()

        # for ignore_rule in ignore_rule_set:
        #     for rule in local_rule_set:
        #         if rule[0][-len(ignore_rule[0]) :] == ignore_rule[0]:
        #             try:
        #                 rule_set.remove(rule)
        #             except KeyError:
        #                 if rule not in local_rule_set:
        #                     raise
        return
        rule_list = list(map(lambda rule: tuple(reversed(rule[0])), rule_set))
        trie = Trie.fromkeys(rule_list)

        for domain, _ in ignore_rule_set:
            covered_domain_set: set[tuple[str]] = set(
                map(
                    lambda domain_tuple: domain_tuple[0], trie.iter_prefix_items(domain)
                )
            )
            # print(covered_domain_set)
            covered_domain_set.intersection_update(rule_set)
            rule_set -= covered_domain_set

    entire_set: set[SplittedRule] = reduce(
        lambda latest_set, current_set: latest_set.union(current_set),
        map(
            lambda rule_set: cast(set[SplittedRule], rule_set.rule_set), RULE_LINK_TUPLE
        ),
    )
    sorted_list = sorted(entire_set, key=lambda rule: rule[0])

    grouped_list = list(
        map(
            lambda rule_tuple: (
                rule_tuple[0],
                set(map(lambda rule: (rule[1], rule[2]), rule_tuple[1])),
            ),
            groupby(sorted_list, key=lambda rule: rule[0]),
        )
    )

    block_rule_set = extract_set(RuleApplication.BLOCK, grouped_list)
    block_ignore_rule_set = extract_set(RuleApplication.BLOCK_IGNORE, grouped_list)
    redirect_rule_set = extract_set(RuleApplication.REDIRECT, grouped_list)
    redirect_ignore_rule_set = extract_set(
        RuleApplication.REDIRECT_IGNORE, grouped_list
    )
    resolve_rule_set = extract_set(RuleApplication.RESOLVE, grouped_list)

    if block_rule_set is not None:
        remove_included(block_rule_set)

        if block_ignore_rule_set is not None:
            remove_ignore(block_rule_set, block_ignore_rule_set)

        if redirect_rule_set is not None:
            remove_ignore(redirect_rule_set, block_rule_set)

        if resolve_rule_set is not None:
            remove_ignore(resolve_rule_set, block_rule_set)

    if redirect_rule_set is not None:
        remove_included(redirect_rule_set)

        if redirect_ignore_rule_set is not None:
            remove_ignore(redirect_rule_set, redirect_ignore_rule_set)

        if resolve_rule_set is not None:
            remove_ignore(resolve_rule_set, redirect_rule_set)

    if resolve_rule_set is not None:
        remove_included(resolve_rule_set)

    config_list: list[str] = encode_smartdns(
        list(block_rule_set) if block_rule_set is not None else None,
        list(redirect_rule_set) if redirect_rule_set is not None else None,
        list(resolve_rule_set) if resolve_rule_set is not None else None,
    )
    config_list.sort()

    config_str: str = "\n".join(config_list) + "\n"

    outfile.write(config_str)
    if outfile != stdout:
        outfile.close()


async def fetch_rule(rule_set: RuleSet, session: aiohttp.ClientSession) -> None:
    async with session.get(rule_set.link, allow_redirects=False) as response:
        rule_set.text = (await response.text(encoding="UTF-8")).splitlines()
        assert rule_set.text, rule_set.link


def process_rule(rule_set: RuleSet) -> None:
    rule_set.strip_text()
    rule_set.split_syntax()
    rule_set.split_domain()


async def async_main() -> None:
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
        await asyncio.gather(*map(fetch_rule, RULE_LINK_TUPLE, repeat(session)))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch rules and generate smartdns config"
    )
    parser.add_argument(
        "outfile",
        nargs="?",
        type=argparse.FileType("w", encoding="UTF-8"),
        default=stdout,
    )
    outfile: TextIOWrapper = parser.parse_args().outfile

    asyncio.run(async_main())

    consume(map(process_rule, RULE_LINK_TUPLE))

    output(outfile)


if __name__ == "__main__":
    main()
