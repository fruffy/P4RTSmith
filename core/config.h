#ifndef BACKENDS_P4TOOLS_MODULES_RTSMITH_CORE_CONFIG_H_
#define BACKENDS_P4TOOLS_MODULES_RTSMITH_CORE_CONFIG_H_

#include <filesystem>
#include <stdexcept>
#include <vector>

#include <toml++/toml.hpp>

#include "backends/p4tools/common/lib/util.h"

namespace P4::P4Tools::RtSmith {

class FuzzerConfig {
 private:
    /// The maximum number of entries we are trying to generate for a table.
    int maxEntryGenCnt = 5;
    // The maximum attempts we are trying to generate an entry.
    int maxAttempts = 100;
    /// The maximum number of tables.
    int maxTables = 5;
    /// The string representations of tables to skip.
    std::vector<std::string> tablesToSkip;
    /// Threshold for deletion.
    uint64_t thresholdForDeletion = 30;
    /// The maximum number of updates.
    size_t maxUpdateCount = 10;
    /// The maximum time (in microseconds) for the update.
    uint64_t maxUpdateTimeInMicroseconds = 100000;
    /// The minimum time (in microseconds) for the update.
    uint64_t minUpdateTimeInMicroseconds = 50000;

 protected:
    /// Setters to modify/override the fuzzer configurations.
    void setMaxEntryGenCnt(const int numEntries);
    void setMaxAttempts(const int numAttempts);
    void setMaxTables(const int numTables);
    void setTablesToSkip(const std::vector<std::string> &tables);
    void setThresholdForDeletion(const uint64_t threshold);
    void setMaxUpdateCount(const size_t count);
    void setMaxUpdateTimeInMicroseconds(const uint64_t micros);
    void setMinUpdateTimeInMicroseconds(const uint64_t micros);

 public:
    // Default constructor.
    FuzzerConfig() = default;

    // Default destructor.
    virtual ~FuzzerConfig() = default;

    /// @brief Override the default fuzzer configurations through the TOML file.
    /// @param path The path to the TOML file.
    void overrideFuzzerConfigs(std::filesystem::path path);

    /// @brief Override the default fuzzer configurations through the string representation of the
    /// configurations of format TOML.
    /// @param configInString The string representation of the configurations.
    void overrideFuzzerConfigsInString(std::string configInString);

    /// @brief Get the TOML node from the TOML result.
    static std::optional<toml::v3::node_view<const toml::v3::node>> getTOMLNode(
        const toml::parse_result &tomlConfig, const std::string &key);

    /// Getters to access the fuzzer configurations.
    [[nodiscard]] int getMaxEntryGenCnt() const { return maxEntryGenCnt; }
    [[nodiscard]] int getMaxAttempts() const { return maxAttempts; }
    [[nodiscard]] int getMaxTables() const { return maxTables; }
    [[nodiscard]] const std::vector<std::string> &getTablesToSkip() const { return tablesToSkip; }
    [[nodiscard]] uint64_t getThresholdForDeletion() const { return thresholdForDeletion; }
    [[nodiscard]] size_t getMaxUpdateCount() const { return maxUpdateCount; }
    [[nodiscard]] uint64_t getMaxUpdateTimeInMicroseconds() const {
        return maxUpdateTimeInMicroseconds;
    }
    [[nodiscard]] uint64_t getMinUpdateTimeInMicroseconds() const {
        return minUpdateTimeInMicroseconds;
    }

    /// @brief Cast the TOML node to a specific type of value (encapsulated in `std::optional`).
    template <typename T>
    static std::optional<T> castTOMLNode(const toml::v3::node_view<const toml::v3::node> &node) {
        if constexpr (std::is_same_v<T, int>) {
            if (node.is_integer()) {
                return node.as_integer()->get();
            } else {
                return std::nullopt;
            }
        } else if constexpr (std::is_same_v<T, uint64_t>) {
            if (node.is_integer()) {
                return node.as_integer()->get();
            } else {
                return std::nullopt;
            }
        } else if constexpr (std::is_same_v<T, size_t>) {
            if (node.is_integer()) {
                return node.as_integer()->get();
            } else {
                return std::nullopt;
            }
        } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            if (node.is_array()) {
                std::vector<std::string> result;
                for (const auto &element : *node.as_array()) {
                    if (element.is_string()) {
                        result.push_back(element.as_string()->get());
                    } else {
                        return std::nullopt;
                    }
                }
                return result;
            } else {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }
};

}  // namespace P4::P4Tools::RtSmith

#endif /* BACKENDS_P4TOOLS_MODULES_RTSMITH_CORE_CONFIG_H_ */
