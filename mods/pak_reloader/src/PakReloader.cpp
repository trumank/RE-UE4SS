#include <PakReloader.hpp>

#include <vector>
#include <unordered_map>
#include <iostream>
#include <ranges>

#include <DynamicOutput/DynamicOutput.hpp>
#include <Helpers/String.hpp>
#include <Unreal/Signatures.hpp>
#include <SigScanner/SinglePassSigScanner.hpp>

#define IMGUI_DEFINE_MATH_OPERATORS
#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>

namespace RC::GUI::PakReloader
{
    using namespace RC::Unreal;

    class IPlatformFile
    {
    };
    struct FPakFile
    {
        void* vftable;
        size_t idk;
        void* idk2;
        FString PakFilename;

    };
    struct FPakListEntry
    {
        uint32_t ReadOrder;
        FPakFile* PakFile;
    };

    class FPakPlatformFile : IPlatformFile
    {
    public:
        void* vftable;
        IPlatformFile* LowerLevel;
        //TArray<FPakListEntry> PakFiles; // can't use TArray because no exported template for FPakListEntry
        FPakListEntry* PakFiles;
        uint32_t PakFilesNum;
        uint32_t PakFilesMax;
    };

    struct DelegateMount
    {
        uint64_t idk1;
        uint64_t idk2;
        uint64_t idk3;
        FPakPlatformFile* pak;
        bool (*fn)(FPakPlatformFile*, FString&, uint32_t);
    };
    struct DelegateUnmount
    {
        uint64_t idk1;
        uint64_t idk2;
        uint64_t idk3;
        FPakPlatformFile* pak;
        bool (*fn)(FPakPlatformFile*, FString&);
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
            SignatureContainer fplatformfilepak_dtor = [&]() -> SignatureContainer {
                return {
                    { { "40 53 56 57 48 83 ec 20 48 8d 05 ?? ?? ?? ?? 4c 89 74 24 50 48 89 01 48 8b f9 e8 ?? ?? ?? ?? 48 8b c8" } },
                    [&](SignatureContainer& self) {
                        uint8_t* data = static_cast<uint8_t*>(self.get_match_address());
                        void* last = nullptr;
                        int num = 0;
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
                                    num += 1;

                                    switch (num)
                                    {
                                        case 3:
                                            MountPak = *(DelegateMount**) ptr;
                                            break;
                                        case 4:
                                            OnUnmountPak = *(DelegateUnmount**) ptr;
                                            break;
                                        case 5:
                                            self.get_did_succeed() = true;
                                            return true;
                                    }
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
                MountPak->fn(MountPak->pak, pak_path, 100);

                m_input_mount.clear();
            }

            for (int i = 0; i < MountPak->pak->PakFilesNum; i++)
            {
                FPakListEntry entry = MountPak->pak->PakFiles[i];

                if (ImGui::Button("unmount"))
                {
                    FString pak_path = entry.PakFile->PakFilename;
                    OnUnmountPak->fn(OnUnmountPak->pak, pak_path);
                }
                ImGui::SameLine();
                if (ImGui::Button("reload"))
                {
                    FString pak_path = entry.PakFile->PakFilename;
                    OnUnmountPak->fn(OnUnmountPak->pak, pak_path);
                    MountPak->fn(MountPak->pak, pak_path, 100);
                }
                ImGui::SameLine();
                ImGui::Text("%s", to_string(entry.PakFile->PakFilename.GetCharArray()).c_str());
            }
        }
        else
        {
            ImGui::Text("Could not find MountPak and UnmountPak delgates");
        }
    }
}
