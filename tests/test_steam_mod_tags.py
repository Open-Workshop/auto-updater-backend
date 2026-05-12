import unittest

from steam.steam_mod import SteamMod


class SteamModTagParsingTests(unittest.TestCase):
    def test_from_html_parses_workshop_tag_groups(self) -> None:
        html = """
        <div class="workshopItemTitle">Example Mod</div>
        <div class="rightDetailsBlock">
            <div data-panel='{"type":"PanelGroup"}' class="workshopTags">
                <span class="workshopTagsTitle">Miscellaneous:&nbsp;</span>
                <a href="https://steamcommunity.com/workshop/browse/?appid=431960&amp;requiredtags[]=Approved">Approved</a>,
                <a href="https://steamcommunity.com/workshop/browse/?appid=431960&amp;requiredtags[]=Customizable">Customizable</a>
            </div>
            <div data-panel='{"type":"PanelGroup"}' class="workshopTags">
                <span class="workshopTagsTitle">Type:&nbsp;</span>
                <a href="https://steamcommunity.com/workshop/browse/?appid=431960&amp;requiredtags[]=Scene">Scene</a>
            </div>
            <div data-panel='{"type":"PanelGroup"}' class="workshopTags">
                <span class="workshopTagsTitle">Age Rating:&nbsp;</span>
                <a href="https://steamcommunity.com/workshop/browse/?appid=431960&amp;requiredtags[]=Everyone">Everyone</a>
            </div>
            <div data-panel='{"type":"PanelGroup"}' class="workshopTags">
                <span class="workshopTagsTitle">Genre:&nbsp;</span>
                <a href="https://steamcommunity.com/workshop/browse/?appid=431960&amp;requiredtags[]=Sci-Fi">Sci-Fi</a>
            </div>
            <div data-panel='{"type":"PanelGroup"}' class="workshopTags">
                <span class="workshopTagsTitle">Resolution:&nbsp;</span>
                <a href="https://steamcommunity.com/workshop/browse/?appid=431960&amp;requiredtags[]=1366+x+768">1366 x 768</a>
            </div>
            <div data-panel='{"type":"PanelGroup"}' class="workshopTags">
                <span class="workshopTagsTitle">Category:&nbsp;</span>
                <a href="https://steamcommunity.com/workshop/browse/?appid=431960&amp;requiredtags[]=Wallpaper">Wallpaper</a>
            </div>
        </div>
        """

        mod = SteamMod.from_html("3720384777", html)

        self.assertEqual(
            mod.tags,
            [
                "Approved",
                "Customizable",
                "Scene",
                "Everyone",
                "Sci-Fi",
                "1366 x 768",
                "Wallpaper",
            ],
        )
        self.assertEqual(
            [(group.name, group.tags) for group in mod.tag_groups],
            [
                ("Miscellaneous", ["Approved", "Customizable"]),
                ("Type", ["Scene"]),
                ("Age Rating", ["Everyone"]),
                ("Genre", ["Sci-Fi"]),
                ("Resolution", ["1366 x 768"]),
                ("Category", ["Wallpaper"]),
            ],
        )


if __name__ == "__main__":
    unittest.main()
