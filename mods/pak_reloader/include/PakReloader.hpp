#ifndef UE4SS_BP_PAK_RELOADER_HPP
#define UE4SS_BP_PAK_RELOADER_HPP

#include <unordered_map>
#include <unordered_set>

#include <Unreal/FFrame.hpp>
#include <Unreal/UStruct.hpp>
#include <Unreal/UObject.hpp>

namespace RC::GUI::PakReloader
{
    using namespace RC::Unreal;

    class PakReloader
    {
    public:
        PakReloader();
        ~PakReloader();

        auto render() -> void;

    private:
        std::string m_input_mount{""};
        bool m_already_scanned{false};
    };
}

#endif // UE4SS_BP_PAK_RELOADER_HPP
