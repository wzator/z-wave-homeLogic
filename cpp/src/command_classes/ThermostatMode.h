//-----------------------------------------------------------------------------
//
//	ThermostatMode.h
//
//	Implementation of the Z-Wave COMMAND_CLASS_THERMOSTAT_MODE
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

#ifndef _ThermostatMode_H
#define _ThermostatMode_H

#include <vector>
#include <string>
#include "command_classes/CommandClass.h"
#include "value_classes/ValueList.h"

namespace OpenZWave
{
	namespace Internal
	{
		namespace CC
		{

			/** \brief Implements COMMAND_CLASS_THERMOSTAT_MODE (0x40), a Z-Wave device command class.
			 * \ingroup CommandClass
			 */
			class ThermostatMode: public CommandClass
			{
				public:
					static CommandClass* Create(uint32 const _homeId, uint8 const _nodeId)
					{
						return new ThermostatMode(_homeId, _nodeId);
					}
					virtual ~ThermostatMode()
					{
					}

					static uint8 const StaticGetCommandClassId()
					{
						return 0x40;
					}
					static string const StaticGetCommandClassName()
					{
						return "COMMAND_CLASS_THERMOSTAT_MODE";
					}

					// From CommandClass
					virtual void ReadXML(TiXmlElement const* _ccElement) override;
					virtual void WriteXML(TiXmlElement* _ccElement) override;
					virtual bool RequestState(uint32 const _requestFlags, uint8 const _instance, Driver::MsgQueue const _queue) override;
					virtual bool RequestValue(uint32 const _requestFlags, uint16 const _getTypeEnum, uint8 const _dummy, Driver::MsgQueue const _queue) override;
					virtual uint8 const GetCommandClassId() const override
					{
						return StaticGetCommandClassId();
					}
					virtual string const GetCommandClassName() const override
					{
						return StaticGetCommandClassName();
					}
					virtual bool HandleMsg(uint8 const* _data, uint32 const _length, uint32 const _instance = 1) override;
					virtual bool SetValue(Internal::VC::Value const& _value) override;
					virtual uint8 GetMaxVersion() override
					{
						return 3;
					}
					virtual void SupervisionSessionSuccess(uint8 _session_id, uint32 const _instance);

				protected:
					virtual void CreateVars(uint8 const _instance) override;

				private:
					ThermostatMode(uint32 const _homeId, uint8 const _nodeId);

					vector<Internal::VC::ValueList::Item> m_supportedModes;
					uint32 m_currentMode; 
			};
		} // namespace CC
	} // namespace Internal
} // namespace OpenZWave

#endif

