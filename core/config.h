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

    /// @brief Get the TOML node from the TOML result and cast it to a specific type of value.
    template <typename T>
    static std::optional<T> getAndCastTOMLNode(const toml::parse_result &tomlConfig,
                                               const std::string &key) {
        if (auto node = tomlConfig[key]) {
            if constexpr (std::is_same_v<T, int> || std::is_same_v<T, uint64_t> ||
                          std::is_same_v<T, size_t>) {
                return castTOMLNode<T>(node);
            } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                if (auto nodeValuePtr = node.as_array()) {
                    std::vector<std::string> result;
                    for (const auto &element : *nodeValuePtr) {
                        if (element.is_string()) {
                            // Get the value of the string out of the `std::optional` encapsulations
                            // and push it to the `result` vector.
                            result.push_back(castTOMLNode<std::string>(element).value());
                        } else {
                            return std::nullopt;
                        }
                    }
                    return std::make_optional(result);
                } else {
                    return std::nullopt;
                }
            } else {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }

    /// @brief Cast the TOML node to a specific type of value (encapsulated in
    /// `std::optional`).
    template <typename T>
    static std::optional<T> castTOMLNode(const toml::v3::node_view<const toml::v3::node> &node) {
        if constexpr (std::is_same_v<T, int> || std::is_same_v<T, uint64_t> ||
                      std::is_same_v<T, size_t>) {
            if (auto nodeValuePtr = node.as_integer()) {
                return std::make_optional(nodeValuePtr->get());
            } else {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }

    /// @brief Cast the TOML node to a specific type of value (encapsulated in
    /// `std::optional`).
    /// This is an overloaded function of the `castTOMLNode` function for the `toml::v3::node`-type
    /// parameter.
    template <typename T>
    static std::optional<T> castTOMLNode(const toml::v3::node &node) {
        if constexpr (std::is_same_v<T, std::string>) {
            if (auto nodeValuePtr = node.as_string()) {
                return std::make_optional(nodeValuePtr->get());
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
