//-----------------------------------------------------------------------------
//
//	ValueByte.cpp
//
//	Represents an 8-bit value
//
//	Copyright (c) 2010 Mal Lansell <openzwave@lansell.org>
//
//	SOFTWARE NOTICE AND LICENSE
//
//	This file is part of OpenZWave.
//
//	OpenZWave is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Lesser General Public License as published
//	by the Free Software Foundation, either version 3 of the License,
//	or (at your option) any later version.
//
//	OpenZWave is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Lesser General Public License for more details.
//
//	You should have received a copy of the GNU Lesser General Public License
//	along with OpenZWave.  If not, see <http://www.gnu.org/licenses/>.
//
//-----------------------------------------------------------------------------

#include <sstream>
#include "tinyxml.h"
#include "value_classes/ValueByte.h"
#include "Msg.h"
#include "platform/Log.h"
#include "Manager.h"
#include <ctime>

namespace OpenZWave
{
	namespace Internal
	{
		namespace VC
		{

//-----------------------------------------------------------------------------
// <ValueByte::ValueByte>
// Constructor
//-----------------------------------------------------------------------------
			ValueByte::ValueByte(uint32 const _homeId, uint8 const _nodeId, ValueID::ValueGenre const _genre, uint8 const _commandClassId, uint8 const _instance, uint16 const _index, string const& _label, string const& _units, bool const _readOnly, bool const _writeOnly, uint8 const _value, uint8 const _pollIntensity) :
					Value(_homeId, _nodeId, _genre, _commandClassId, _instance, _index, ValueID::ValueType_Byte, _label, _units, _readOnly, _writeOnly, false, _pollIntensity), m_value(_value), m_valueCheck(false), m_targetValue(0)
			{
				m_min = 0;
				m_max = 255;
			}

//-----------------------------------------------------------------------------
// <ValueByte::ValueByte>
// Constructor (from XML)
//-----------------------------------------------------------------------------
			ValueByte::ValueByte()
			{
				m_min = 0;
				m_max = 255;
			}

			std::string const ValueByte::GetAsString() const
			{
				stringstream ss;
				ss << (uint32) GetValue();
				return ss.str();
			}

			bool ValueByte::SetFromString(string const& _value)
			{
				uint32 val = (uint32) atoi(_value.c_str());
				if (val < 256)
				{
					return Set((uint8) val);
				}
				return false;
			}

//-----------------------------------------------------------------------------
// <ValueByte::ReadXML>
// Apply settings from XML
//-----------------------------------------------------------------------------
			void ValueByte::ReadXML(uint32 const _homeId, uint8 const _nodeId, uint8 const _commandClassId, TiXmlElement const* _valueElement)
			{
				Value::ReadXML(_homeId, _nodeId, _commandClassId, _valueElement);

				int intVal;
				if (TIXML_SUCCESS == _valueElement->QueryIntAttribute("value", &intVal))
				{
					m_value = (uint8) intVal;
				}
				else
				{
					Log::Write(LogLevel_Info, "Missing default byte value from xml configuration: node %d, class 0x%02x, instance %d, index %d", _nodeId, _commandClassId, GetID().GetInstance(), GetID().GetIndex());
				}
			}

//-----------------------------------------------------------------------------
// <ValueByte::WriteXML>
// Write ourselves to an XML document
//-----------------------------------------------------------------------------
			void ValueByte::WriteXML(TiXmlElement* _valueElement)
			{
				Value::WriteXML(_valueElement);

				char str[8];
				snprintf(str, sizeof(str), "%d", m_value);
				_valueElement->SetAttribute("value", str);
			}

//-----------------------------------------------------------------------------
// <ValueByte::Set>
// Set a new value in the device
//-----------------------------------------------------------------------------
			bool ValueByte::Set(uint8 const _value)
			{
				// create a temporary copy of this value to be submitted to the Set() call and set its value to the function param
				ValueByte* tempValue = new ValueByte(*this);
				tempValue->m_value = _value;

				// Save the new value to be stored when the device confirms the value was set successfully, 
				m_newValue = _value;

				// Set the value in the device.
				bool ret = ((Value*) tempValue)->Set();

				// clean up the temporary value
				delete tempValue;

				return ret;
			}

//-----------------------------------------------------------------------------
// <ValueByte::SetTargetValue>
// Set the Value Target (Used for Automatic Refresh)
//-----------------------------------------------------------------------------
			void ValueByte::SetTargetValue(uint8 const _target, uint32 _duration)
			{
				m_targetValueSet = true;
				m_targetValue = _target;
				m_duration = _duration;
			}

//-----------------------------------------------------------------------------
// <ValueByte::OnValueRefreshed>
// A value in a device has been refreshed
//-----------------------------------------------------------------------------
			void ValueByte::OnValueRefreshed(uint8 const _value)
			{
				switch (VerifyRefreshedValue((void*) &m_value, (void*) &m_valueCheck, (void*) &_value, (void*) &m_targetValue, ValueID::ValueType_Byte))
				{
					case 0:		// value hasn't changed, nothing to do
						break;
					case 1:		// value has changed (not confirmed yet), save _value in m_valueCheck
						m_valueCheck = _value;
						break;
					case 2:		// value has changed (confirmed), save _value in m_value
						m_value = _value;
						break;
					case 3:		// all three values are different, so wait for next refresh to try again
						break;
				}
			}
		} // namespace VC
	} // namespace Internal
} // namespace OpenZWave
