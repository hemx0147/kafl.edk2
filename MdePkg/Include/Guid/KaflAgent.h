/** @file
  GUID and variable name definitions for kAFL fuzzing agent.

**/

#ifndef __KAFL_AGENT_GUID_H__
#define __KAFL_AGENT_GUID_H__

//
// Vendor GUID for the kAFL agent state variable
// {9E44C873-2D36-4605-B146-69A23D7D42B9}
//
#define KAFL_AGENT_STATE_VARIABLE_GUID \
  { 0x9e44c873, 0x2d36, 0x4605, { 0xb1, 0x46, 0x69, 0xa2, 0x3d, 0x7d, 0x42, 0xb9 } }


//
// name for the kAFL agent state variable
//
#define KAFL_AGENT_STATE_VARIABLE_NAME  L"KaflAgentState"

extern EFI_GUID gKaflAgentStateVariableGuid;

#endif
