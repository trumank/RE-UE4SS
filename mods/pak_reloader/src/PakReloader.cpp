#include <PakReloader.hpp>

#include <vector>
#include <unordered_map>
#include <iostream>
#include <ranges>

#include <DynamicOutput/DynamicOutput.hpp>
#include <Helpers/String.hpp>
#include <Unreal/Signatures.hpp>
#include <Unreal/UnrealVersion.hpp>
#include <SigScanner/SinglePassSigScanner.hpp>

#define IMGUI_DEFINE_MATH_OPERATORS
#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>

namespace RC::GUI::PakReloader
{
    using namespace RC::Unreal;

    struct V422_FPakFile
    {
        FString PakFilename;
    };
    struct V427_FPakFile
    {
        void* idk1;
        void* idk2;
        void* idk3;
        FString PakFilename;

    };
    struct FPakFile
    {
        FString PakFilename()
        {
            if (Version::IsBelow(4, 27))
                return std::bit_cast<V422_FPakFile*>(this)->PakFilename;
            else
                return std::bit_cast<V427_FPakFile*>(this)->PakFilename;
        }
    };

    struct FPakListEntry
    {
        uint32_t ReadOrder;
        FPakFile* PakFile;
    };

    struct FPakPlatformFile
    {
        void* vftable;
        void* LowerLevel;
        //TArray<FPakListEntry> PakFiles; // can't use TArray because no exported template for FPakListEntry
        FPakListEntry* PakFiles;
        uint32_t PakFilesNum;
        uint32_t PakFilesMax;
    };

    struct V422_DelegateMount
    {
        void* idk1;
        FPakPlatformFile* pak;
        bool (*fn)(FPakPlatformFile*, FString&, uint32_t);
    };
    struct V427_DelegateMount
    {
        void* idk1;
        void* idk2;
        void* idk3;
        FPakPlatformFile* pak;
        bool (*fn)(FPakPlatformFile*, FString&, uint32_t);
    };
    struct DelegateMount
    {
        FPakPlatformFile* Pak()
        {
            if (Version::IsBelow(4, 27))
                return std::bit_cast<V422_DelegateMount*>(this)->pak;
            else
                return std::bit_cast<V427_DelegateMount*>(this)->pak;
        }
        bool Call(FString& str, uint32_t order)
        {
            if (Version::IsBelow(4, 27))
                return std::bit_cast<V422_DelegateMount*>(this)->fn(this->Pak(), str, order);
            else
                return std::bit_cast<V427_DelegateMount*>(this)->fn(this->Pak(), str, order);
        }
    };

    struct V422_DelegateUnmount
    {
        void* idk1;
        FPakPlatformFile* pak;
        bool (*fn)(FPakPlatformFile*, FString&);
    };
    struct V427_DelegateUnmount
    {
        void* idk1;
        void* idk2;
        void* idk3;
        FPakPlatformFile* pak;
        bool (*fn)(FPakPlatformFile*, FString&);
    };
    struct DelegateUnmount
    {
        FPakPlatformFile* Pak()
        {
            if (Version::IsBelow(4, 27))
                return std::bit_cast<V422_DelegateUnmount*>(this)->pak;
            else
                return std::bit_cast<V427_DelegateUnmount*>(this)->pak;
        }
        bool Call(FString& str)
        {
            if (Version::IsBelow(4, 27))
                return std::bit_cast<V422_DelegateUnmount*>(this)->fn(this->Pak(), str);
            else
                return std::bit_cast<V427_DelegateUnmount*>(this)->fn(this->Pak(), str);
        }
    };

    DelegateMount* MountPak = nullptr;
    DelegateUnmount* OnUnmountPak = nullptr;

    PakReloader::PakReloader() { }
    PakReloader::~PakReloader() { }

    auto PakReloader::render() -> void
    {
        if (!m_already_scanned && (OnUnmountPak == nullptr || MountPak == nullptr))
        {
            m_already_scanned = true;
            enum DtorPattern
            {
                V422,
                V427,
            };
            SignatureContainer fplatformfilepak_dtor = [&]() -> SignatureContainer {
                return {
                    {
                        {
                            "40 56 48 83 ec 40 48 89 5c 24 50 48 8d 05 ?? ?? ?? ?? 48 89 7c 24 60 48 8b f1 4c 89 64 24 38 4c 89 6c 24 30",
                            DtorPattern::V422,
                        },
                        {
                            "40 53 56 57 48 83 ec 20 48 8d 05 ?? ?? ?? ?? 4c 89 74 24 50 48 89 01 48 8b f9 e8 ?? ?? ?? ?? 48 8b c8",
                            DtorPattern::V427,
                        },
                    },
                    [&](SignatureContainer& self) {
                        Output::send<LogLevel::Warning>(STR("[PakReloader]: found match: {}\n"), (void*)self.get_match_address());

                        int num = 0;
                        const auto signature_identifier = static_cast<const DtorPattern>(self.get_signatures()[self.get_index_into_signatures()].custom_data);
                        switch (signature_identifier)
                        {
                            case DtorPattern::V422:
                                num = 2;
                                break;
                            case DtorPattern::V427:
                                num = 0;
                                break;
                        }

                        uint8_t* data = static_cast<uint8_t*>(self.get_match_address());
                        void* last = nullptr;
                        for (uint8_t* i : std::views::iota(data) | std::views::take(3000))
                        {
                            // look for 'mov rcx,[rel address]'
                            if (i[0] == 0x48 && i[1] == 0x8b && i[2] == 0x0d)
                            {
                                // mov found, resolve RIP
                                int32_t rip;
                                memcpy(&rip, i + 3, sizeof(rip));

                                void* ptr = i + 3 + 4 + rip;

                                if (ptr != last)
                                {
                                    last = ptr;

                                    Output::send<LogLevel::Warning>(STR("[PakReloader]: found delegate: {} ({})\n"), ptr, num);

                                    switch (num)
                                    {
                                        case 2:
                                            MountPak = *(DelegateMount**) ptr;
                                            break;
                                        case 3:
                                            OnUnmountPak = *(DelegateUnmount**) ptr;
                                            self.get_did_succeed() = true;
                                            return true;
                                    }

                                    num += 1;
                                }
                            }
                        }

                        return false;
                    },
                    [&](const SignatureContainer& self) {
                        if (!self.get_did_succeed())
                        {
                            Output::send<LogLevel::Warning>(STR("[PakReloader]: Pak delegates not found\n"));
                        }
                    }
                };
            }();

            SinglePassScanner::SignatureContainerMap container_map;
            std::vector<SignatureContainer> container;
            container.emplace_back(fplatformfilepak_dtor);
            container_map.emplace(ScanTarget::Core, container);
            SinglePassScanner::start_scan(container_map);
        }
        if (OnUnmountPak != nullptr && MountPak != nullptr)
        {
            bool mount_input = ImGui::InputText("##input-mount", &m_input_mount, ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::SameLine();
            bool mount_button = ImGui::Button("mount");

            if (mount_button || mount_input)
            {
                std::wstring wstr = to_wstring(m_input_mount);
                FString pak_path(wstr.c_str());
                MountPak->Call(pak_path, 100);

                m_input_mount.clear();
            }

            for (int i = 0; i < MountPak->Pak()->PakFilesNum; i++)
            {
                FPakListEntry entry = MountPak->Pak()->PakFiles[i];

                if (ImGui::Button("unmount"))
                {
                    FString pak_path = entry.PakFile->PakFilename();
                    OnUnmountPak->Call(pak_path);
                }
                ImGui::SameLine();
                if (ImGui::Button("reload"))
                {
                    FString pak_path = entry.PakFile->PakFilename();
                    OnUnmountPak->Call(pak_path);
                    MountPak->Call(pak_path, 100);
                }
                ImGui::SameLine();
                ImGui::Text("%s", to_string(entry.PakFile->PakFilename().GetCharArray()).c_str());
            }
        }
        else
        {
            ImGui::Text("Could not find MountPak and UnmountPak delgates");
        }
    }
}
