//-----------------------------------------------------------------------------
//
//	SwitchMultilevel.h
//
//	Implementation of the Z-Wave COMMAND_CLASS_SWITCH_MULTILEVEL
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

#ifndef _SwitchMultilevel_H
#define _SwitchMultilevel_H

#include "command_classes/CommandClass.h"

namespace OpenZWave
{
	namespace Internal
	{
		namespace CC
		{

			/** \brief Implements COMMAND_CLASS_SWITCH_MULTILEVEL (0x26), a Z-Wave device command class.
			 * \ingroup CommandClass
			 */
			class SwitchMultilevel: public CommandClass
			{
				public:
					static CommandClass* Create(uint32 const _homeId, uint8 const _nodeId)
					{
						return new SwitchMultilevel(_homeId, _nodeId);
					}
					virtual ~SwitchMultilevel()
					{
					}

					static uint8 const StaticGetCommandClassId()
					{
						return 0x26;
					}
					static string const StaticGetCommandClassName()
					{
						return "COMMAND_CLASS_SWITCH_MULTILEVEL";
					}

					// From CommandClass
					virtual bool RequestState(uint32 const _requestFlags, uint8 const _instance, Driver::MsgQueue const _queue) override;
					virtual bool RequestValue(uint32 const _requestFlags, uint16 const _index, uint8 const _instance, Driver::MsgQueue const _queue) override;
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
					virtual void SetValueBasic(uint8 const _instance, uint8 const _value) override;

					virtual uint8 GetMaxVersion() override
					{
						return 4;
					}
					virtual void SupervisionSessionSuccess(uint8 _session_id, uint32 const _instance);

				protected:
					virtual void CreateVars(uint8 const _instance) override;

				private:
					enum SwitchMultilevelDirection
					{
						SwitchMultilevelDirection_Up = 0,
						SwitchMultilevelDirection_Down,
						SwitchMultilevelDirection_Inc,
						SwitchMultilevelDirection_Dec
					};

					SwitchMultilevel(uint32 const _homeId, uint8 const _nodeId) :
							CommandClass(_homeId, _nodeId)
					{
					}

					bool SetLevel(uint8 const _instance, uint8 const _level);
					bool StartLevelChange(uint8 const _instance, SwitchMultilevelDirection const _direction);
					bool StopLevelChange(uint8 const _instance);
			};
		} // namespace CC
	} // namespace Internal
} // namespace OpenZWave

#endif

