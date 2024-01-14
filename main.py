import asyncio
import aiohttp
import requests
import logging
import time


async def main_loop():
    print("За работу!(")

    logging.basicConfig(level=logging.INFO, filename="working.log", filemode="w",
                        format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger().addHandler(logging.StreamHandler())
    currect_page:int = 0

    try:
        while True:
            time.sleep(1)

            url = f"https://api.openworkshop.su/list/mods/?page_size=40&page={currect_page}&sort=iUPDATE_DATE&general=false&primary_sources=%5B%22steam%22%5D"
            result = requests.get(url=url).json()
            mods = result.get("results", [])

            print("")
            if len(mods) > 0:
                logging.info(f"Страница: {currect_page}")

                for mod_id in mods:
                    await check_mod(mod_id["id"])

                currect_page += 1
            else:
                logging.info(f"Сброс подсчета страниц на странице: {currect_page}")
                currect_page = 0
    except:
        logging.critical("Во время основного цикла произошла неизвестная ошибка!!")

async def check_mod(mod_id):
    try:
        async with aiohttp.ClientSession() as session:
            url = f'https://api.openworkshop.su/info/mod/{mod_id}?dependencies=true&short_description=false&description=false&dates=false&general=false&game=false'
            async with session.get(url=url) as response:
                result = await response.json()
                dependencies = result.get('dependencies', [])

                if len(dependencies) > 0:
                    durl = f'https://api.openworkshop.su/condition/mod/{dependencies}'.replace(' ', '')
                    async with session.get(url=durl) as dresponse:
                        dresult = await dresponse.json()

                        non_downloaded_depen = []

                        for depen in dependencies:
                            if str(depen) not in dresult:
                                non_downloaded_depen.append(fetch_url(depen))

                        if len(non_downloaded_depen) > 0:
                            logging.info(f"У мода {mod_id} обнаружено {len(non_downloaded_depen)} из {len(dependencies)} не установленных зависимостей!")
                            await asyncio.gather(*non_downloaded_depen)

            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.openworkshop.su/update/steam/{mod_id}") as response:
                    if response.status == 202:
                        logging.info(f'Мод {mod_id} поставлен на обновление! ^_^')
                    elif response.status == 404:
                        logging.warning(f'Мод {mod_id} удалён со Steam! O_o')
    except:
        logging.critical(f"Во время работы с модом {mod_id} произошла неизвестная ошибка!!")



async def fetch_url(depen):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.openworkshop.su/download/steam/{depen}") as response:
                if response.status != 202:
                    logging.error(f'Загрузка зависимости {depen} завершилась с ошибкой {response.status} :(')
    except:
        logging.critical(f"Во время работы с зависимостью {depen} произошла неизвестная ошибка!!")


if __name__ == "__main__":
    asyncio.run(main_loop())