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
        if (auto maxEntryGenCntOpt = castTOMLNode<int>(maxEntryGenCntNodeOpt.value())) {
            setMaxEntryGenCnt(maxEntryGenCntOpt.value());
        } else {
            // Generate an error if the configuration is not an integer.
            error(
                "ControlPlaneSmith: The maximum number of entries to generate must be an "
                "integer.");
        }
    }

    if (const auto maxAttemptsNodeOpt = getTOMLNode(tomlConfig, "maxAttempts")) {
        if (auto maxAttemptsOpt = castTOMLNode<int>(maxAttemptsNodeOpt.value())) {
            setMaxAttempts(maxAttemptsOpt.value());
        } else {
            error("ControlPlaneSmith: The maximum number of attempts must be an integer.");
        }
    }

    if (const auto maxTablesNodeOpt = getTOMLNode(tomlConfig, "maxTables")) {
        if (auto maxTablesOpt = castTOMLNode<int>(maxTablesNodeOpt.value())) {
            setMaxTables(maxTablesOpt.value());
        } else {
            error("ControlPlaneSmith: The maximum number of tables must be an integer.");
        }
    }

    if (const auto tablesToSkipNodeOpt = getTOMLNode(tomlConfig, "tablesToSkip")) {
        if (auto tablesToSkipConfigOpt =
                castTOMLNode<std::vector<std::string>>(tablesToSkipNodeOpt.value())) {
            const std::vector<std::string> &tablesToSkipConfig = tablesToSkipConfigOpt.value();
            setTablesToSkip(tablesToSkipConfig);
        } else {
            error("ControlPlaneSmith: The tables to skip must be an array.");
        }
    }

    if (const auto thresholdForDeletionNodeOpt = getTOMLNode(tomlConfig, "thresholdForDeletion")) {
        if (auto thresholdForDeletionOpt =
                castTOMLNode<uint64_t>(thresholdForDeletionNodeOpt.value())) {
            setThresholdForDeletion(static_cast<uint64_t>(thresholdForDeletionOpt.value()));
        } else {
            error("ControlPlaneSmith: The threshold for deletion must be an integer.");
        }
    }

    if (const auto maxUpdateCountNodeOpt = getTOMLNode(tomlConfig, "maxUpdateCount")) {
        if (auto maxUpdateCountOpt = castTOMLNode<size_t>(maxUpdateCountNodeOpt.value())) {
            setMaxUpdateCount(static_cast<size_t>(maxUpdateCountOpt.value()));
        } else {
            error("ControlPlaneSmith: The maximum number of updates must be an integer.");
        }
    }

    if (const auto maxUpdateTimeInMicrosecondsNodeOpt =
            getTOMLNode(tomlConfig, "maxUpdateTimeInMicroseconds")) {
        if (auto maxUpdateTimeInMicrosecondsOpt =
                castTOMLNode<uint64_t>(maxUpdateTimeInMicrosecondsNodeOpt.value())) {
            setMaxUpdateTimeInMicroseconds(
                static_cast<uint64_t>(maxUpdateTimeInMicrosecondsOpt.value()));
        } else {
            error("ControlPlaneSmith: The maximum wait time must be an integer.");
        }
    }
    if (const auto minUpdateTimeInMicrosecondsNodeOpt =
            getTOMLNode(tomlConfig, "minUpdateTimeInMicroseconds")) {
        if (auto minUpdateTimeInMicrosecondsOpt =
                castTOMLNode<uint64_t>(minUpdateTimeInMicrosecondsNodeOpt.value())) {
            setMinUpdateTimeInMicroseconds(
                static_cast<uint64_t>(minUpdateTimeInMicrosecondsOpt.value()));
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
        if (auto maxEntryGenCntOpt = castTOMLNode<int>(maxEntryGenCntNodeOpt.value())) {
            setMaxEntryGenCnt(maxEntryGenCntOpt.value());
        } else {
            // Generate an error if the configuration is not an integer.
            error(
                "ControlPlaneSmith: The maximum number of entries to generate must be an "
                "integer.");
        }
    }

    if (const auto maxAttemptsNodeOpt = getTOMLNode(tomlConfig, "maxAttempts")) {
        if (auto maxAttemptsOpt = castTOMLNode<int>(maxAttemptsNodeOpt.value())) {
            setMaxAttempts(maxAttemptsOpt.value());
        } else {
            error("ControlPlaneSmith: The maximum number of attempts must be an integer.");
        }
    }

    if (const auto maxTablesNodeOpt = getTOMLNode(tomlConfig, "maxTables")) {
        if (auto maxTablesOpt = castTOMLNode<int>(maxTablesNodeOpt.value())) {
            setMaxTables(maxTablesOpt.value());
        } else {
            error("ControlPlaneSmith: The maximum number of tables must be an integer.");
        }
    }

    if (const auto tablesToSkipNodeOpt = getTOMLNode(tomlConfig, "tablesToSkip")) {
        if (auto tablesToSkipConfigOpt =
                castTOMLNode<std::vector<std::string>>(tablesToSkipNodeOpt.value())) {
            const std::vector<std::string> &tablesToSkipConfig = tablesToSkipConfigOpt.value();
            setTablesToSkip(tablesToSkipConfig);
        } else {
            error("ControlPlaneSmith: The tables to skip must be an array.");
        }
    }

    if (const auto thresholdForDeletionNodeOpt = getTOMLNode(tomlConfig, "thresholdForDeletion")) {
        if (auto thresholdForDeletionOpt =
                castTOMLNode<uint64_t>(thresholdForDeletionNodeOpt.value())) {
            setThresholdForDeletion(static_cast<uint64_t>(thresholdForDeletionOpt.value()));
        } else {
            error("ControlPlaneSmith: The threshold for deletion must be an integer.");
        }
    }

    if (const auto maxUpdateCountNodeOpt = getTOMLNode(tomlConfig, "maxUpdateCount")) {
        if (auto maxUpdateCountOpt = castTOMLNode<size_t>(maxUpdateCountNodeOpt.value())) {
            setMaxUpdateCount(static_cast<size_t>(maxUpdateCountOpt.value()));
        } else {
            error("ControlPlaneSmith: The maximum number of updates must be an integer.");
        }
    }

    if (const auto maxUpdateTimeInMicrosecondsNodeOpt =
            getTOMLNode(tomlConfig, "maxUpdateTimeInMicroseconds")) {
        if (auto maxUpdateTimeInMicrosecondsOpt =
                castTOMLNode<uint64_t>(maxUpdateTimeInMicrosecondsNodeOpt.value())) {
            setMaxUpdateTimeInMicroseconds(
                static_cast<uint64_t>(maxUpdateTimeInMicrosecondsOpt.value()));
        } else {
            error("ControlPlaneSmith: The maximum wait time must be an integer.");
        }
    }
    if (const auto minUpdateTimeInMicrosecondsNodeOpt =
            getTOMLNode(tomlConfig, "minUpdateTimeInMicroseconds")) {
        if (auto minUpdateTimeInMicrosecondsOpt =
                castTOMLNode<uint64_t>(minUpdateTimeInMicrosecondsNodeOpt.value())) {
            setMinUpdateTimeInMicroseconds(
                static_cast<uint64_t>(minUpdateTimeInMicrosecondsOpt.value()));
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
