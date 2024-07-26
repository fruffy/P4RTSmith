#include "backends/p4tools/modules/p4rtsmith/core/fuzzer.h"

#include "backends/p4tools/common/lib/util.h"
#include "control-plane/bytestrings.h"
#include "control-plane/p4infoApi.h"

namespace P4Tools::RTSmith {

/// @brief Produce bytes in form of std::string given bitwidth.
/// @param bitwidth
/// @return A random bytes of length bitwidth in form of std::string.
std::string produceBytes(int bitwidth) {
    auto value = Utils::getRandConstantForWidth(bitwidth)->value;
    std::optional<std::string> valueStr = P4::ControlPlaneAPI::stringReprConstant(value, bitwidth);
    BUG_CHECK(valueStr.has_value(), "Failed to produce bytes, maybe value < 0?");
    return valueStr.value();
}

/// @brief Produce bytes in form of std::string given bitwidth.
/// @param bitwidth
/// @param value
/// @return A bytes of value of length bitwidth in form of std::string.
std::string produceBytes(int bitwidth, big_int value) {
    std::optional<std::string> valueStr = P4::ControlPlaneAPI::stringReprConstant(value, bitwidth);
    BUG_CHECK(valueStr.has_value(), "Failed to produce bytes, maybe value%1% < 0?", value.str());
    return valueStr.value();
}

p4::v1::FieldMatch_Exact P4RuntimeFuzzer::produceFieldMatch_Exact(int bitwidth) {
    p4::v1::FieldMatch_Exact protoExact;
    protoExact.set_value(produceBytes(bitwidth));
    return protoExact;
}

p4::v1::FieldMatch_LPM P4RuntimeFuzzer::produceFieldMatch_LPM(int bitwidth) {
    p4::v1::FieldMatch_LPM protoLPM;
    protoLPM.set_value(produceBytes(bitwidth));
    protoLPM.set_prefix_len(Utils::getRandInt(0, bitwidth));
    return protoLPM;
}

p4::v1::FieldMatch_Ternary P4RuntimeFuzzer::produceFieldMatch_Ternary(int bitwidth) {
    p4::v1::FieldMatch_Ternary protoTernary;
    protoTernary.set_value(produceBytes(bitwidth));
    // TODO: use random mask
    protoTernary.set_mask(produceBytes(bitwidth, /*value=*/0));
    return protoTernary;
}

p4::v1::FieldMatch_Optional P4RuntimeFuzzer::produceFieldMatch_Optional(int bitwidth) {
    p4::v1::FieldMatch_Optional protoOptional;
    protoOptional.set_value(produceBytes(bitwidth));
    return protoOptional;
}

p4::v1::Action_Param P4RuntimeFuzzer::produceActionParam(
    const p4::config::v1::Action_Param &param) {
    p4::v1::Action_Param protoParam;
    protoParam.set_param_id(param.id());
    protoParam.set_value(produceBytes(param.bitwidth()));
    return protoParam;
}

p4::v1::Action P4RuntimeFuzzer::produceTableAction(
    const google::protobuf::RepeatedPtrField<p4::config::v1::ActionRef> &action_refs,
    const google::protobuf::RepeatedPtrField<p4::config::v1::Action> &actions) {
    p4::v1::Action protoAction;

    auto action_index = Utils::getRandInt(action_refs.size() - 1);
    auto action_ref_id = action_refs[action_index].id();

    auto action =
        P4::ControlPlaneAPI::findP4InfoObject(actions.begin(), actions.end(), action_ref_id);
    auto action_id = action->preamble().id();
    auto params = action->params();

    protoAction.set_action_id(action_id);
    for (auto &param : action->params()) {
        protoAction.add_params()->CopyFrom(produceActionParam(param));
    }

    return protoAction;
}

uint32_t P4RuntimeFuzzer::producePriority(
    const google::protobuf::RepeatedPtrField<p4::config::v1::MatchField> &matchFields) {
    for (auto i = 0; i < matchFields.size(); i++) {
        auto match = matchFields[i];
        auto matchType = match.match_type();
        if (matchType == p4::config::v1::MatchField::TERNARY ||
            matchType == p4::config::v1::MatchField::RANGE ||
            matchType == p4::config::v1::MatchField::OPTIONAL) {
            auto value = Utils::getRandConstantForWidth(32)->value;
            auto priority = static_cast<int>(value);
            return priority;
        }
    }

    return 0;
}

p4::v1::FieldMatch P4RuntimeFuzzer::produceMatchField(p4::config::v1::MatchField &match) {
    p4::v1::FieldMatch protoMatch;
    protoMatch.set_field_id(match.id());

    auto matchType = match.match_type();
    auto bitwidth = match.bitwidth();

    switch (matchType) {
        case p4::config::v1::MatchField::EXACT:
            protoMatch.mutable_exact()->CopyFrom(produceFieldMatch_Exact(bitwidth));
            break;
        case p4::config::v1::MatchField::LPM:
            protoMatch.mutable_lpm()->CopyFrom(produceFieldMatch_LPM(bitwidth));
            break;
        case p4::config::v1::MatchField::TERNARY:
            protoMatch.mutable_ternary()->CopyFrom(produceFieldMatch_Ternary(bitwidth));
            break;
        case p4::config::v1::MatchField::OPTIONAL:
            protoMatch.mutable_optional()->CopyFrom(produceFieldMatch_Optional(bitwidth));
            break;
        default:
            P4C_UNIMPLEMENTED("Match type %1% not supported for P4RuntimeFuzzer yet",
                              p4::config::v1::MatchField::MatchType_Name(matchType));
    }
    return protoMatch;
}

p4::v1::TableEntry P4RuntimeFuzzer::produceTableEntry(
    const p4::config::v1::Table &table,
    const google::protobuf::RepeatedPtrField<p4::config::v1::Action> &actions) {
    p4::v1::TableEntry protoEntry;

    // set table id
    const auto &pre_t = table.preamble();
    protoEntry.set_table_id(pre_t.id());

    // add matches
    const auto &matchFields = table.match_fields();
    for (auto i = 0; i < matchFields.size(); i++) {
        auto match = matchFields[i];
        protoEntry.add_match()->CopyFrom(produceMatchField(match));
    }

    // set priority
    auto priority = producePriority(matchFields);
    protoEntry.set_priority(priority);

    // add action
    const auto &action_refs = table.action_refs();
    auto protoAction = produceTableAction(action_refs, actions);
    *protoEntry.mutable_action()->mutable_action() = protoAction;

    return protoEntry;
}

bfrt_proto::KeyField_Exact BFRuntimeFuzzer::produceKeyField_Exact(int bitwidth) {
    bfrt_proto::KeyField_Exact protoExact;
    protoExact.set_value(produceBytes(bitwidth));
    return protoExact;
}

bfrt_proto::KeyField_LPM BFRuntimeFuzzer::produceKeyField_LPM(int bitwidth) {
    bfrt_proto::KeyField_LPM protoLPM;
    protoLPM.set_value(produceBytes(bitwidth));
    protoLPM.set_prefix_len(Utils::getRandInt(0, bitwidth));
    return protoLPM;
}

bfrt_proto::KeyField_Ternary BFRuntimeFuzzer::produceKeyField_Ternary(int bitwidth) {
    bfrt_proto::KeyField_Ternary protoTernary;
    protoTernary.set_value(produceBytes(bitwidth));
    // TODO: use 0 for mask for now because setting mask to random value may not make sense.
    protoTernary.set_mask(produceBytes(bitwidth, 0));
    return protoTernary;
}

bfrt_proto::KeyField_Optional BFRuntimeFuzzer::produceKeyField_Optional(int bitwidth) {
    bfrt_proto::KeyField_Optional protoOptional;
    protoOptional.set_value(produceBytes(bitwidth));
    return protoOptional;
}

bfrt_proto::DataField BFRuntimeFuzzer::produceDataField(const p4::config::v1::Action_Param &param) {
    bfrt_proto::DataField protoDataField;
    protoDataField.set_field_id(param.id());
    protoDataField.set_stream(produceBytes(param.bitwidth()));
    return protoDataField;
}

bfrt_proto::TableData BFRuntimeFuzzer::produceTableData(
    const google::protobuf::RepeatedPtrField<p4::config::v1::ActionRef> &action_refs,
    const google::protobuf::RepeatedPtrField<p4::config::v1::Action> &actions) {
    bfrt_proto::TableData protoTableData;

    auto action_index = Utils::getRandInt(action_refs.size() - 1);
    auto action_ref_id = action_refs[action_index].id();

    auto action =
        P4::ControlPlaneAPI::findP4InfoObject(actions.begin(), actions.end(), action_ref_id);
    protoTableData.set_action_id(action->preamble().id());
    for (auto &param : action->params()) {
        *protoTableData.add_fields() = produceDataField(param);
    }

    return protoTableData;
}

bfrt_proto::KeyField BFRuntimeFuzzer::produceKeyField(const p4::config::v1::MatchField &match) {
    bfrt_proto::KeyField protoKeyField;
    protoKeyField.set_field_id(match.id());
    auto matchType = match.match_type();
    auto bitwidth = match.bitwidth();

    switch (matchType) {
        case p4::config::v1::MatchField::EXACT:
            protoKeyField.mutable_exact()->CopyFrom(produceKeyField_Exact(bitwidth));
            break;
        case p4::config::v1::MatchField::LPM:
            protoKeyField.mutable_lpm()->CopyFrom(produceKeyField_LPM(bitwidth));
            break;
        case p4::config::v1::MatchField::TERNARY:
            protoKeyField.mutable_ternary()->CopyFrom(produceKeyField_Ternary(bitwidth));
            break;
        case p4::config::v1::MatchField::OPTIONAL:
            protoKeyField.mutable_optional()->CopyFrom(produceKeyField_Optional(bitwidth));
            break;
        default:
            P4C_UNIMPLEMENTED("Match type %1% not supported for BFRuntimeFuzzer yet",
                              p4::config::v1::MatchField::MatchType_Name(matchType));
    }
    return protoKeyField;
}

bfrt_proto::TableEntry BFRuntimeFuzzer::produceTableEntry(
    const p4::config::v1::Table &table,
    const google::protobuf::RepeatedPtrField<p4::config::v1::Action> &actions) {
    bfrt_proto::TableEntry protoEntry;

    // set table id
    const auto &pre_t = table.preamble();
    protoEntry.set_table_id(pre_t.id());

    // add matches
    const auto &matchFields = table.match_fields();
    for (auto i = 0; i < matchFields.size(); i++) {
        auto match = matchFields[i];
        protoEntry.mutable_key()->add_fields()->CopyFrom(produceKeyField(matchFields[i]));
    }

    // add action
    const auto &action_refs = table.action_refs();
    protoEntry.mutable_data()->CopyFrom(produceTableData(action_refs, actions));

    return protoEntry;
}

}  // namespace P4Tools::RTSmith
