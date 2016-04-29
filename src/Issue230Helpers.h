#pragma once

template<typename MType,typename MValue>
bool isIssue230(MType& m_type, MValue& m_value){
    if(m_value.number_float != 23.42)
        return false;
    if(m_type.bits.exp_cap == 0 and
        m_type.bits.exp_plus == 0 and
        m_type.bits.has_exp == 1 and
        m_type.bits.parsed == 1 and
        m_type.bits.precision == 0 and
        m_type.bits.type == 7)
        return true;
    return false;
}