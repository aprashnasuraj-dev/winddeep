# Security Policy

## Reporting a vulnerability in Windeep

Please avoid publishing an unpatched vulnerability in a public issue when it could put users at material risk. Contact the repository maintainer privately through GitHub's available private reporting channel when enabled, or use the maintainer contact listed on the GitHub profile.

Include:

- affected version/commit;
- reproduction steps;
- security impact;
- suggested mitigation when known;
- whether the issue has been disclosed elsewhere.

## Supported versions

Until the first stable release, security fixes target the latest `main` branch and the most recent tagged prerelease/release where practical.

## Authorized-use scope

Windeep is intended for systems the operator owns or has explicit permission to test. Users are responsible for target-program scope, rate limits, testing windows, data-handling rules, and local law.

Project maintainers do not grant authorization to test third-party systems. A public hostname, IP address, mobile app, smart contract, or repository is not automatically permission to assess it.

## Safe-harbor expectations for this repository

Good-faith research **against Windeep itself** is welcome when it avoids privacy violations, destructive testing, service disruption, credential theft, and access to data beyond what is necessary to demonstrate the issue. This statement does not create safe harbor for testing third-party targets through Windeep.

## Secrets

Never commit API keys, access tokens, private certificates, session material, or target data. Use local environment variables or secret stores. GitHub Actions secrets must not be printed to logs.
