#include "backends/p4tools/modules/rtsmith/core/config.cpp"
#include "backends/p4tools/modules/rtsmith/test/core/rtsmith_test.h"

namespace P4::P4Tools::Test {

namespace {

using namespace P4::literals;

class TOMLFuzzerConfigurationTest : public RtSmithTest {};

// Test of overriding fuzzer configurations via configurations specified in a TOML file.
TEST_F(TOMLFuzzerConfigurationTest, OverrideFuzzerConfigurationsViaTOMLFile) {
    auto source = generateTestProgram(R"(
    // Drop the packet.
    action acl_drop() {
        mark_to_drop(sm);
    }

    table drop_table {
        key = {
            hdr.eth_hdr.dst_addr : ternary @name("dst_eth");
        }
        actions = {
            acl_drop();
            @defaultonly NoAction();
        }
    }

    apply {
        if (hdr.eth_hdr.isValid()) {
            drop_table.apply();
        }
    })");
    auto autoContext = SetUp("bmv2", "v1model");
    auto &rtSmithOptions = RtSmith::RtSmithOptions::get();
    rtSmithOptions.target = "bmv2"_cs;
    rtSmithOptions.arch = "v1model"_cs;

    std::string configFilePath = "test/configuration.toml";
    rtSmithOptions.setFuzzerConfigPath(configFilePath);
    // Check if the fuzzer configuration path is set (and is set correctly).
    ASSERT_TRUE(rtSmithOptions.fuzzerConfigPath().has_value());
    ASSERT_EQ(rtSmithOptions.fuzzerConfigPath().value(), configFilePath);

    auto rtSmithResultOpt = P4::P4Tools::RtSmith::RtSmith::generateConfig(source, rtSmithOptions);
    // Check if the `RtSmithResult` object is generated successfully.
    ASSERT_TRUE(rtSmithResultOpt.has_value());

    auto compilerResult =
        P4::P4Tools::RtSmith::RtSmith::generateCompilerResult(source, rtSmithOptions);
    // Check if the `compilerResult` object is generated successfully.
    ASSERT_TRUE(compilerResult.has_value());

    const auto *programInfo = P4::P4Tools::RtSmith::RtSmithTarget::produceProgramInfo(
        compilerResult.value(), rtSmithOptions);
    // Check if the `programInfo` object is generated successfully.
    ASSERT_TRUE(programInfo != nullptr);

    // Parse the fuzzer configurations from the TOML file.
    toml::parse_result tomlConfig;
    try {
        tomlConfig = toml::parse_file(configFilePath);
    } catch (const toml::parse_error &e) {
        error("P4RuntimeSmith: Failed to parse fuzzer configuration file: %1%", e.what());
    }
    int maxEntryGenCntConfig;
    int maxAttemptsConfig;
    int maxTablesConfig;
    std::vector<std::string> tablesToSkipConfig;
    uint64_t thresholdForDeletionConfig;
    size_t maxUpdateCountConfig;
    uint64_t maxUpdateTimeInMicrosecondsConfig;
    uint64_t minUpdateTimeInMicrosecondsConfig;
    auto maxEntryGenCntNode = tomlConfig["maxEntryGenCnt"];
    // Check if the node exists.
    if (!!maxEntryGenCntNode) {
        // Check if the node represents an integer, meaning whether the configuration provided is
        // valid.
        if (maxEntryGenCntNode.type() == toml::node_type::integer) {
            maxEntryGenCntConfig = maxEntryGenCntNode.value<int>().value();
        } else {
            error("P4RuntimeSmith: The maximum number of entries to generate must be an integer.");
        }
    } else {
        // If the node does not exist, throw an error that indicates the configuration must be
        // provided.
        error("P4RuntimeSmith: The maximum number of entries to generate must be provided.");
    }
    auto maxAttemptsNode = tomlConfig["maxAttempts"];
    if (!!maxAttemptsNode) {
        if (maxAttemptsNode.type() == toml::node_type::integer) {
            maxAttemptsConfig = maxAttemptsNode.value<int>().value();
        } else {
            error("P4RuntimeSmith: The maximum number of attempts must be an integer.");
        }
    } else {
        error("P4RuntimeSmith: The maximum number of attempts must be provided.");
    }
    auto maxTablesNode = tomlConfig["maxTables"];
    if (!!maxTablesNode) {
        if (maxTablesNode.type() == toml::node_type::integer) {
            maxTablesConfig = maxTablesNode.value<int>().value();
        } else {
            error("P4RuntimeSmith: The maximum number of tables must be an integer.");
        }
    } else {
        error("P4RuntimeSmith: The maximum number of tables must be provided.");
    }
    auto tablesToSkipNode = tomlConfig["tablesToSkip"];
    if (!!tablesToSkipNode) {
        if (tablesToSkipNode.type() == toml::node_type::array) {
            const auto *expectedStringRepresentations = tablesToSkipNode.as_array();
            for (const auto &expectedStringRepresentation : *expectedStringRepresentations) {
                if (const auto *str = expectedStringRepresentation.as_string()) {
                    tablesToSkipConfig.push_back(str->get());
                } else {
                    error("P4RuntimeSmith: The tables to skip must be strings.");
                }
            }
        } else {
            error("P4RuntimeSmith: The tables to skip must be an array.");
        }
    } else {
        error("P4RuntimeSmith: The tables to skip must be provided.");
    }
    auto thresholdForDeletionNode = tomlConfig["thresholdForDeletion"];
    if (!!thresholdForDeletionNode) {
        if (thresholdForDeletionNode.type() == toml::node_type::integer) {
            thresholdForDeletionConfig = thresholdForDeletionNode.value<uint64_t>().value();
        } else {
            error("P4RuntimeSmith: The threshold for deletion must be an integer.");
        }
    } else {
        error("P4RuntimeSmith: The threshold for deletion must be provided.");
    }
    auto maxUpdateCountNode = tomlConfig["maxUpdateCount"];
    if (!!maxUpdateCountNode) {
        if (maxUpdateCountNode.type() == toml::node_type::integer) {
            maxUpdateCountConfig = maxUpdateCountNode.value<size_t>().value();
        } else {
            error("P4RuntimeSmith: The maximum number of updates must be an integer.");
        }
    } else {
        error("P4RuntimeSmith: The maximum number of updates must be provided.");
    }
    auto maxUpdateTimeInMicrosecondsNode = tomlConfig["maxUpdateTimeInMicroseconds"];
    auto minUpdateTimeInMicrosecondsNode = tomlConfig["minUpdateTimeInMicroseconds"];
    if (!!maxUpdateTimeInMicrosecondsNode) {
        if (maxUpdateTimeInMicrosecondsNode.type() == toml::node_type::integer) {
            maxUpdateTimeInMicrosecondsConfig =
                maxUpdateTimeInMicrosecondsNode.value<uint64_t>().value();
        } else {
            error("P4RuntimeSmith: The maximum wait time must be an integer.");
        }
    } else {
        error("P4RuntimeSmith: The maximum wait time must be provided.");
    }
    if (!!minUpdateTimeInMicrosecondsNode) {
        if (minUpdateTimeInMicrosecondsNode.type() == toml::node_type::integer) {
            minUpdateTimeInMicrosecondsConfig =
                minUpdateTimeInMicrosecondsNode.value<uint64_t>().value();
        } else {
            error("P4RuntimeSmith: The minimum wait time must be an integer.");
        }
    } else {
        error("P4RuntimeSmith: The minimum wait time must be provided.");
    }

    // Check if the fuzzer configurations are overridden correctly.
    const P4::P4Tools::RtSmith::FuzzerConfig &fuzzerConfig = programInfo->getFuzzerConfig();
    ASSERT_EQ(fuzzerConfig.getMaxEntryGenCnt(), maxEntryGenCntConfig);
    ASSERT_EQ(fuzzerConfig.getMaxAttempts(), maxAttemptsConfig);
    ASSERT_EQ(fuzzerConfig.getMaxTables(), maxTablesConfig);
    for (size_t i = 0; i < tablesToSkipConfig.size(); i++) {
        ASSERT_EQ(fuzzerConfig.getTablesToSkip()[i], tablesToSkipConfig[i]);
    }
    ASSERT_EQ(fuzzerConfig.getThresholdForDeletion(), thresholdForDeletionConfig);
    ASSERT_EQ(fuzzerConfig.getMaxUpdateCount(), maxUpdateCountConfig);
    ASSERT_EQ(fuzzerConfig.getMaxUpdateTimeInMicroseconds(), maxUpdateTimeInMicrosecondsConfig);
    ASSERT_EQ(fuzzerConfig.getMinUpdateTimeInMicroseconds(), minUpdateTimeInMicrosecondsConfig);
}

// Test of overriding fuzzer configurations via the string representation of the configurations of
// format TOML.
TEST_F(TOMLFuzzerConfigurationTest, OverrideFuzzerConfigurationsViaTOMLString) {
    auto source = generateTestProgram(R"(
    // Drop the packet.
    action acl_drop() {
        mark_to_drop(sm);
    }

    table drop_table {
        key = {
            hdr.eth_hdr.dst_addr : ternary @name("dst_eth");
        }
        actions = {
            acl_drop();
            @defaultonly NoAction();
        }
    }

    apply {
        if (hdr.eth_hdr.isValid()) {
            drop_table.apply();
        }
    })");
    auto autoContext = SetUp("bmv2", "v1model");
    auto &rtSmithOptions = RtSmith::RtSmithOptions::get();
    rtSmithOptions.target = "bmv2"_cs;
    rtSmithOptions.arch = "v1model"_cs;

    std::string configInString = R"(
    maxEntryGenCnt = 10
    maxAttempts = 200
    maxTables = 10
    tablesToSkip = ["table1", "table2"]
    thresholdForDeletion = 50
    maxUpdateCount = 20
    maxUpdateTimeInMicroseconds = 100001
    minUpdateTimeInMicroseconds = 50001
    )";
    rtSmithOptions.setFuzzerConfigString(configInString);
    // Check if the fuzzer configuration string is set (and is set correctly).
    ASSERT_TRUE(rtSmithOptions.fuzzerConfigString().has_value());
    ASSERT_EQ(rtSmithOptions.fuzzerConfigString().value(), configInString);

    auto rtSmithResultOpt = P4::P4Tools::RtSmith::RtSmith::generateConfig(source, rtSmithOptions);
    // Check if the `RtSmithResult` object is generated successfully.
    ASSERT_TRUE(rtSmithResultOpt.has_value());

    auto compilerResult =
        P4::P4Tools::RtSmith::RtSmith::generateCompilerResult(source, rtSmithOptions);
    // Check if the `compilerResult` object is generated successfully.
    ASSERT_TRUE(compilerResult.has_value());

    const auto *programInfo = P4::P4Tools::RtSmith::RtSmithTarget::produceProgramInfo(
        compilerResult.value(), rtSmithOptions);
    // Check if the `programInfo` object is generated successfully.
    ASSERT_TRUE(programInfo != nullptr);

    // Parse the fuzzer configurations from the string.
    toml::parse_result tomlConfig;
    try {
        tomlConfig = toml::parse(configInString);
    } catch (const toml::parse_error &e) {
        error("P4RuntimeSmith: Failed to parse fuzzer configuration string: %1%", e.what());
    }

    // Check if the fuzzer configurations are overridden correctly.
    const P4::P4Tools::RtSmith::FuzzerConfig &fuzzerConfig = programInfo->getFuzzerConfig();
    // Check if the node exists. If not, do nothing and leave the default configuration as is.
    if (const auto maxEntryGenCntNodeOpt =
            P4::P4Tools::RtSmith::FuzzerConfig::getTOMLNode(tomlConfig, "maxEntryGenCnt")) {
        // Check if the node represents an integer, meaning whether the configuration provided is
        // valid.
        if (maxEntryGenCntNodeOpt.value().type() == toml::node_type::integer) {
            ASSERT_EQ(fuzzerConfig.getMaxEntryGenCnt(),
                      maxEntryGenCntNodeOpt.value().value<int>().value());
        } else {
            error("P4RuntimeSmith: The maximum number of entries to generate must be an integer.");
        }
    }

    if (const auto maxAttemptsNodeOpt =
            P4::P4Tools::RtSmith::FuzzerConfig::getTOMLNode(tomlConfig, "maxAttempts")) {
        if (maxAttemptsNodeOpt.value().type() == toml::node_type::integer) {
            ASSERT_EQ(fuzzerConfig.getMaxAttempts(),
                      maxAttemptsNodeOpt.value().value<int>().value());
        } else {
            error("P4RuntimeSmith: The maximum number of attempts must be an integer.");
        }
    }

    if (const auto maxTablesNodeOpt =
            P4::P4Tools::RtSmith::FuzzerConfig::getTOMLNode(tomlConfig, "maxTables")) {
        if (maxTablesNodeOpt.value().type() == toml::node_type::integer) {
            ASSERT_EQ(fuzzerConfig.getMaxTables(), maxTablesNodeOpt.value().value<int>().value());
        } else {
            error("P4RuntimeSmith: The maximum number of tables must be an integer.");
        }
    }

    // TODO(zzmic): Fix the following test case.
    // std::vector<std::string> tablesToSkip = fuzzerConfig.getTablesToSkip();
    // if (const auto tablesToSkipNodeOpt =
    // P4::P4Tools::RtSmith::FuzzerConfig::getTOMLNode(tomlConfig, "tablesToSkip")) {
    //     if (tablesToSkipNodeOpt.value().type() == toml::node_type::array) {
    //         const auto *expectedStringRepresentations = tablesToSkipNodeOpt.value().as_array();
    //         for (int i = 0; i < expectedStringRepresentations->size(); i++) {
    //             if (const auto str = expectedStringRepresentations->at(i).as_string()) {
    //                 ASSERT_EQ(tablesToSkip[i], str);
    //             } else {
    //                 error("P4RuntimeSmith: The tables to skip must be strings.");
    //             }
    //         }
    //     } else {
    //         error("P4RuntimeSmith: The tables to skip must be an array.");
    //     }
    // }

    if (const auto thresholdForDeletionNodeOpt =
            P4::P4Tools::RtSmith::FuzzerConfig::getTOMLNode(tomlConfig, "thresholdForDeletion")) {
        if (thresholdForDeletionNodeOpt.value().type() == toml::node_type::integer) {
            ASSERT_EQ(fuzzerConfig.getThresholdForDeletion(),
                      thresholdForDeletionNodeOpt.value().value<uint64_t>().value());
        } else {
            error("P4RuntimeSmith: The threshold for deletion must be an integer.");
        }
    }

    if (const auto maxUpdateCountNodeOpt =
            P4::P4Tools::RtSmith::FuzzerConfig::getTOMLNode(tomlConfig, "maxUpdateCount")) {
        if (maxUpdateCountNodeOpt.value().type() == toml::node_type::integer) {
            ASSERT_EQ(fuzzerConfig.getMaxUpdateCount(),
                      maxUpdateCountNodeOpt.value().value<size_t>().value());
        } else {
            error("P4RuntimeSmith: The maximum number of updates must be an integer.");
        }
    }

    if (const auto maxUpdateTimeInMicrosecondsNodeOpt =
            P4::P4Tools::RtSmith::FuzzerConfig::getTOMLNode(tomlConfig,
                                                            "maxUpdateTimeInMicroseconds")) {
        if (maxUpdateTimeInMicrosecondsNodeOpt.value().type() == toml::node_type::integer) {
            ASSERT_EQ(fuzzerConfig.getMaxUpdateTimeInMicroseconds(),
                      maxUpdateTimeInMicrosecondsNodeOpt.value().value<uint64_t>().value());
        } else {
            error("P4RuntimeSmith: The maximum wait time must be an integer.");
        }
    }
    if (const auto minUpdateTimeInMicrosecondsNodeOpt =
            P4::P4Tools::RtSmith::FuzzerConfig::getTOMLNode(tomlConfig,
                                                            "minUpdateTimeInMicroseconds")) {
        if (minUpdateTimeInMicrosecondsNodeOpt.value().type() == toml::node_type::integer) {
            ASSERT_EQ(fuzzerConfig.getMinUpdateTimeInMicroseconds(),
                      minUpdateTimeInMicrosecondsNodeOpt.value().value<uint64_t>().value());
        } else {
            error("P4RuntimeSmith: The minimum wait time must be an integer.");
        }
    }
}

}  // anonymous namespace

}  // namespace P4::P4Tools::Test
