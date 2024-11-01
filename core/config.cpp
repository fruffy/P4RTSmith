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
    // Check if the node exists and can be casted to a pointer to a node representation of an
    // integer. If not, do nothing and leave the default configuration as is.
    if (const auto maxEntryGenCntValueOpt = getAndCastTOMLNode<int>(tomlConfig, "maxEntryGenCnt")) {
        setMaxEntryGenCnt(maxEntryGenCntValueOpt.value());
    } else {
        // Generate an error if the configuration is not an integer.
        error(
            "ControlPlaneSmith: The maximum number of entries to generate must be an "
            "integer.");
    }

    if (const auto maxAttemptsValueOpt = getAndCastTOMLNode<int>(tomlConfig, "maxAttempts")) {
        setMaxAttempts(maxAttemptsValueOpt.value());
    } else {
        error("ControlPlaneSmith: The maximum number of attempts must be an integer.");
    }

    if (const auto maxTablesValueOpt = getAndCastTOMLNode<int>(tomlConfig, "maxTables")) {
        setMaxTables(maxTablesValueOpt.value());
    } else {
        error("ControlPlaneSmith: The maximum number of tables must be an integer.");
    }

    if (const auto tablesToSkipValueOpt =
            getAndCastTOMLNode<std::vector<std::string>>(tomlConfig, "tablesToSkip")) {
        setTablesToSkip(tablesToSkipValueOpt.value());
    } else {
        error("ControlPlaneSmith: The tables to skip must be an array.");
    }

    if (const auto thresholdForDeletionValueOpt =
            getAndCastTOMLNode<uint64_t>(tomlConfig, "thresholdForDeletion")) {
        setThresholdForDeletion(static_cast<uint64_t>(thresholdForDeletionValueOpt.value()));
    } else {
        error("ControlPlaneSmith: The threshold for deletion must be an integer.");
    }

    if (const auto maxUpdateCountValueOpt =
            getAndCastTOMLNode<size_t>(tomlConfig, "maxUpdateCount")) {
        setMaxUpdateCount(static_cast<size_t>(maxUpdateCountValueOpt.value()));
    } else {
        error("ControlPlaneSmith: The maximum number of updates must be an integer.");
    }

    if (const auto maxUpdateTimeInMicrosecondsValueOpt =
            getAndCastTOMLNode<uint64_t>(tomlConfig, "maxUpdateTimeInMicroseconds")) {
        setMaxUpdateTimeInMicroseconds(
            static_cast<uint64_t>(maxUpdateTimeInMicrosecondsValueOpt.value()));
    } else {
        error("ControlPlaneSmith: The maximum wait time must be an integer.");
    }
    if (const auto minUpdateTimeInMicrosecondsValueOpt =
            getAndCastTOMLNode<uint64_t>(tomlConfig, "minUpdateTimeInMicroseconds")) {
        setMinUpdateTimeInMicroseconds(
            static_cast<uint64_t>(minUpdateTimeInMicrosecondsValueOpt.value()));
    } else {
        error("ControlPlaneSmith: The minimum wait time must be an integer.");
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
    // Check if the node exists and can be casted to a pointer to a node representation of an
    // integer. If not, do nothing and leave the default configuration as is.
    if (const auto maxEntryGenCntValueOpt = getAndCastTOMLNode<int>(tomlConfig, "maxEntryGenCnt")) {
        setMaxEntryGenCnt(maxEntryGenCntValueOpt.value());
    } else {
        // Generate an error if the configuration is not an integer.
        error(
            "ControlPlaneSmith: The maximum number of entries to generate must be an "
            "integer.");
    }

    if (const auto maxAttemptsValueOpt = getAndCastTOMLNode<int>(tomlConfig, "maxAttempts")) {
        setMaxAttempts(maxAttemptsValueOpt.value());
    } else {
        error("ControlPlaneSmith: The maximum number of attempts must be an integer.");
    }

    if (const auto maxTablesValueOpt = getAndCastTOMLNode<int>(tomlConfig, "maxTables")) {
        setMaxTables(maxTablesValueOpt.value());
    } else {
        error("ControlPlaneSmith: The maximum number of tables must be an integer.");
    }

    if (const auto tablesToSkipValueOpt =
            getAndCastTOMLNode<std::vector<std::string>>(tomlConfig, "tablesToSkip")) {
        setTablesToSkip(tablesToSkipValueOpt.value());
    } else {
        error("ControlPlaneSmith: The tables to skip must be an array.");
    }

    if (const auto thresholdForDeletionValueOpt =
            getAndCastTOMLNode<uint64_t>(tomlConfig, "thresholdForDeletion")) {
        setThresholdForDeletion(static_cast<uint64_t>(thresholdForDeletionValueOpt.value()));
    } else {
        error("ControlPlaneSmith: The threshold for deletion must be an integer.");
    }

    if (const auto maxUpdateCountValueOpt =
            getAndCastTOMLNode<size_t>(tomlConfig, "maxUpdateCount")) {
        setMaxUpdateCount(static_cast<size_t>(maxUpdateCountValueOpt.value()));
    } else {
        error("ControlPlaneSmith: The maximum number of updates must be an integer.");
    }

    if (const auto maxUpdateTimeInMicrosecondsValueOpt =
            getAndCastTOMLNode<uint64_t>(tomlConfig, "maxUpdateTimeInMicroseconds")) {
        setMaxUpdateTimeInMicroseconds(
            static_cast<uint64_t>(maxUpdateTimeInMicrosecondsValueOpt.value()));
    } else {
        error("ControlPlaneSmith: The maximum wait time must be an integer.");
    }
    if (const auto minUpdateTimeInMicrosecondsValueOpt =
            getAndCastTOMLNode<uint64_t>(tomlConfig, "minUpdateTimeInMicroseconds")) {
        setMinUpdateTimeInMicroseconds(
            static_cast<uint64_t>(minUpdateTimeInMicrosecondsValueOpt.value()));
    } else {
        error("ControlPlaneSmith: The minimum wait time must be an integer.");
    }
}

}  // namespace P4::P4Tools::RtSmith
