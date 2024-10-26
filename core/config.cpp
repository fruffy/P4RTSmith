#include "backends/p4tools/modules/rtsmith/core/config.h"

#include "lib/error.h"

namespace P4::P4Tools::RtSmith {

void FuzzerConfig::setMaxEntryGenCnt(const int numEntries) {
    if (numEntries < 0) {
        error(
            "ControlPlaneSmith: The maximum number of entries to generate must be a non-negative "
            "integer.");
    }
    maxEntryGenCnt = numEntries;
}

void FuzzerConfig::setMaxAttempts(const int numAttempts) {
    if (numAttempts <= 0) {
        error("ControlPlaneSmith: The number of attempts must be a positive integer.");
    }
    maxAttempts = numAttempts;
}

void FuzzerConfig::setMaxTables(const int numTables) {
    if (numTables < 0) {
        error("ControlPlaneSmith: The maximum number of tables must be a non-negative integer.");
    }
    maxTables = numTables;
}

void FuzzerConfig::setThresholdForDeletion(const uint64_t threshold) {
    thresholdForDeletion = threshold;
}

void FuzzerConfig::setTablesToSkip(const std::vector<std::string> &tables) {
    tablesToSkip = tables;
}

void FuzzerConfig::setMaxUpdateCount(const size_t count) { maxUpdateCount = count; }

void FuzzerConfig::setMaxUpdateTimeInMicroseconds(const uint64_t micros) {
    if (micros <= 0) {
        error("ControlPlaneSmith: The maximum wait time must be a positive integer.");
    }
    maxUpdateTimeInMicroseconds = micros;
}
void FuzzerConfig::setMinUpdateTimeInMicroseconds(const uint64_t micros) {
    if (micros <= 0) {
        error("ControlPlaneSmith: The minimum wait time must be a positive integer.");
    }
    minUpdateTimeInMicroseconds = micros;
}

void FuzzerConfig::overrideFuzzerConfigs(std::filesystem::path path) {
    toml::parse_result tomlConfig;
    try {
        // Note that the parameter fed into the `parse_file` function should be of (or could be
        // converted to) type `std::string_view`.
        tomlConfig = toml::parse_file(path.string());
    } catch (const toml::parse_error &e) {
        error("ControlPlaneSmith: Failed to parse fuzzer configuration file: %1%", e.what());
    }

    // For the following blocks, retrieve the configurations from the TOML file and override the
    // default configurations if they comply with the constraints.
    // Check if the node exists. If not, do nothing and leave the default configuration as is.
    if (const auto maxEntryGenCntNodeOpt = getTOMLNode(tomlConfig, "maxEntryGenCnt")) {
        // Check if the node represents an integer, meaning whether the configuration provided is
        // valid.
        if (maxEntryGenCntNodeOpt.value().type() == toml::node_type::integer) {
            int maxEntryGenCntConfig = maxEntryGenCntNodeOpt.value().value<int>().value();
            setMaxEntryGenCnt(maxEntryGenCntConfig);
        } else {
            error(
                "ControlPlaneSmith: The maximum number of entries to generate must be an integer.");
        }
    }

    if (const auto maxAttemptsNodeOpt = getTOMLNode(tomlConfig, "maxAttempts")) {
        if (maxAttemptsNodeOpt.value().type() == toml::node_type::integer) {
            int maxAttemptsConfig = maxAttemptsNodeOpt.value().value<int>().value();
            setMaxAttempts(maxAttemptsConfig);
        } else {
            error("ControlPlaneSmith: The maximum number of attempts must be an integer.");
        }
    }

    if (const auto maxTablesNodeOpt = getTOMLNode(tomlConfig, "maxTables")) {
        if (maxTablesNodeOpt.value().type() == toml::node_type::integer) {
            int maxTablesConfig = maxTablesNodeOpt.value().value<int>().value();
            setMaxTables(maxTablesConfig);
        } else {
            error("ControlPlaneSmith: The maximum number of tables must be an integer.");
        }
    }

    if (const auto tablesToSkipNodeOpt = getTOMLNode(tomlConfig, "tablesToSkip")) {
        if (tablesToSkipNodeOpt.value().type() == toml::node_type::array) {
            std::vector<std::string> tablesToSkipConfig;
            const auto *expectedStringRepresentations = tablesToSkipNodeOpt.value().as_array();
            for (const auto &expectedStringRepresentation : *expectedStringRepresentations) {
                if (const auto *str = expectedStringRepresentation.as_string()) {
                    tablesToSkipConfig.push_back(str->get());
                } else {
                    error("ControlPlaneSmith: The tables to skip must be strings.");
                }
            }
            setTablesToSkip(tablesToSkipConfig);
        } else {
            error("ControlPlaneSmith: The tables to skip must be an array.");
        }
    }

    if (const auto thresholdForDeletionNodeOpt = getTOMLNode(tomlConfig, "thresholdForDeletion")) {
        if (thresholdForDeletionNodeOpt.value().type() == toml::node_type::integer) {
            uint64_t thresholdForDeletionConfig =
                thresholdForDeletionNodeOpt.value().value<uint64_t>().value();
            setThresholdForDeletion(thresholdForDeletionConfig);
        } else {
            error("ControlPlaneSmith: The threshold for deletion must be an integer.");
        }
    }

    if (const auto maxUpdateCountNodeOpt = getTOMLNode(tomlConfig, "maxUpdateCount")) {
        if (maxUpdateCountNodeOpt.value().type() == toml::node_type::integer) {
            size_t maxUpdateCountConfig = maxUpdateCountNodeOpt.value().value<size_t>().value();
            setMaxUpdateCount(maxUpdateCountConfig);
        } else {
            error("ControlPlaneSmith: The maximum number of updates must be an integer.");
        }
    }

    if (const auto maxUpdateTimeInMicrosecondsNodeOpt =
            getTOMLNode(tomlConfig, "maxUpdateTimeInMicroseconds")) {
        if (maxUpdateTimeInMicrosecondsNodeOpt.value().type() == toml::node_type::integer) {
            uint64_t maxUpdateTimeInMicrosecondsConfig =
                maxUpdateTimeInMicrosecondsNodeOpt.value().value<uint64_t>().value();
            setMaxUpdateTimeInMicroseconds(maxUpdateTimeInMicrosecondsConfig);
        } else {
            error("ControlPlaneSmith: The maximum wait time must be an integer.");
        }
    }
    if (const auto minUpdateTimeInMicrosecondsNodeOpt =
            getTOMLNode(tomlConfig, "minUpdateTimeInMicroseconds")) {
        if (minUpdateTimeInMicrosecondsNodeOpt.value().type() == toml::node_type::integer) {
            uint64_t minUpdateTimeInMicrosecondsConfig =
                minUpdateTimeInMicrosecondsNodeOpt.value().value<uint64_t>().value();
            setMinUpdateTimeInMicroseconds(minUpdateTimeInMicrosecondsConfig);
        } else {
            error("ControlPlaneSmith: The minimum wait time must be an integer.");
        }
    }
}

void FuzzerConfig::overrideFuzzerConfigsInString(std::string configInString) {
    toml::parse_result tomlConfig;
    try {
        // Note that the parameter fed into the `parse` function should be of (or could be
        // converted to) type `std::string_view`.
        tomlConfig = toml::parse(configInString);
    } catch (const toml::parse_error &e) {
        error("ControlPlaneSmith: Failed to parse fuzzer configuration string: %1%", e.what());
    }

    // For the following blocks, retrieve the configurations from the TOML file and override the
    // default configurations if they comply with the constraints.
    // Check if the node exists. If not, do nothing and leave the default configuration as is.
    if (const auto maxEntryGenCntNodeOpt = getTOMLNode(tomlConfig, "maxEntryGenCnt")) {
        // Check if the node represents an integer, meaning whether the configuration provided is
        // valid.
        if (maxEntryGenCntNodeOpt.value().type() == toml::node_type::integer) {
            int maxEntryGenCntConfig = maxEntryGenCntNodeOpt.value().value<int>().value();
            setMaxEntryGenCnt(maxEntryGenCntConfig);
        } else {
            error(
                "ControlPlaneSmith: The maximum number of entries to generate must be an integer.");
        }
    }

    if (const auto maxAttemptsNodeOpt = getTOMLNode(tomlConfig, "maxAttempts")) {
        if (maxAttemptsNodeOpt.value().type() == toml::node_type::integer) {
            int maxAttemptsConfig = maxAttemptsNodeOpt.value().value<int>().value();
            setMaxAttempts(maxAttemptsConfig);
        } else {
            error("ControlPlaneSmith: The maximum number of attempts must be an integer.");
        }
    }

    if (const auto maxTablesNodeOpt = getTOMLNode(tomlConfig, "maxTables")) {
        if (maxTablesNodeOpt.value().type() == toml::node_type::integer) {
            int maxTablesConfig = maxTablesNodeOpt.value().value<int>().value();
            setMaxTables(maxTablesConfig);
        } else {
            error("ControlPlaneSmith: The maximum number of tables must be an integer.");
        }
    }

    if (const auto tablesToSkipNodeOpt = getTOMLNode(tomlConfig, "tablesToSkip")) {
        if (tablesToSkipNodeOpt.value().type() == toml::node_type::array) {
            std::vector<std::string> tablesToSkipConfig;
            const auto *expectedStringRepresentations = tablesToSkipNodeOpt.value().as_array();
            for (const auto &expectedStringRepresentation : *expectedStringRepresentations) {
                if (const auto *str = expectedStringRepresentation.as_string()) {
                    tablesToSkipConfig.push_back(str->get());
                } else {
                    error("ControlPlaneSmith: The tables to skip must be strings.");
                }
            }
            setTablesToSkip(tablesToSkipConfig);
        } else {
            error("ControlPlaneSmith: The tables to skip must be an array.");
        }
    }

    if (const auto thresholdForDeletionNodeOpt = getTOMLNode(tomlConfig, "thresholdForDeletion")) {
        if (thresholdForDeletionNodeOpt.value().type() == toml::node_type::integer) {
            uint64_t thresholdForDeletionConfig =
                thresholdForDeletionNodeOpt.value().value<uint64_t>().value();
            setThresholdForDeletion(thresholdForDeletionConfig);
        } else {
            error("ControlPlaneSmith: The threshold for deletion must be an integer.");
        }
    }

    if (const auto maxUpdateCountNodeOpt = getTOMLNode(tomlConfig, "maxUpdateCount")) {
        if (maxUpdateCountNodeOpt.value().type() == toml::node_type::integer) {
            size_t maxUpdateCountConfig = maxUpdateCountNodeOpt.value().value<size_t>().value();
            setMaxUpdateCount(maxUpdateCountConfig);
        } else {
            error("ControlPlaneSmith: The maximum number of updates must be an integer.");
        }
    }

    if (const auto maxUpdateTimeInMicrosecondsNodeOpt =
            getTOMLNode(tomlConfig, "maxUpdateTimeInMicroseconds")) {
        if (maxUpdateTimeInMicrosecondsNodeOpt.value().type() == toml::node_type::integer) {
            uint64_t maxUpdateTimeInMicrosecondsConfig =
                maxUpdateTimeInMicrosecondsNodeOpt.value().value<uint64_t>().value();
            setMaxUpdateTimeInMicroseconds(maxUpdateTimeInMicrosecondsConfig);
        } else {
            error("ControlPlaneSmith: The maximum wait time must be an integer.");
        }
    }
    if (const auto minUpdateTimeInMicrosecondsNodeOpt =
            getTOMLNode(tomlConfig, "minUpdateTimeInMicroseconds")) {
        if (minUpdateTimeInMicrosecondsNodeOpt.value().type() == toml::node_type::integer) {
            uint64_t minUpdateTimeInMicrosecondsConfig =
                minUpdateTimeInMicrosecondsNodeOpt.value().value<uint64_t>().value();
            setMinUpdateTimeInMicroseconds(minUpdateTimeInMicrosecondsConfig);
        } else {
            error("ControlPlaneSmith: The minimum wait time must be an integer.");
        }
    }
}

std::optional<toml::v3::node_view<const toml::v3::node>> FuzzerConfig::getTOMLNode(
    const toml::parse_result &tomlConfig, const std::string &key) {
    if (auto node = tomlConfig[key]) {
        return std::make_optional(node);
    }
    return std::nullopt;
}

}  // namespace P4::P4Tools::RtSmith
