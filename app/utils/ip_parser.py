from selenium import webdriver
from selenium.webdriver.common.by import By

URL = "https://spys.one/proxies/"

driver = webdriver.Chrome()
driver.get(URL)

for country in range(2, 100):
    IP = []

    button_country = driver.find_element(
        By.XPATH,
        "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[2]/option["
        + str(country)
        + "]",
    )
    button_country.click()

    button_type_all = driver.find_element(
        By.XPATH,
        "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[6]/option[1]",
    )
    button_type_all.click()
    button_type_all = driver.find_element(
        By.XPATH,
        "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[6]/option[1]",
    )
    type_all_selected = button_type_all.get_attribute("selected")
    button_500 = driver.find_element(
        By.XPATH,
        "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[1]/option[6]",
    )
    button_500.click()
    button_500 = driver.find_element(
        By.XPATH,
        "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[1]/option[6]",
    )
    max_ip_selected = button_500.get_attribute("selected")

    print(max_ip_selected, type_all_selected)
    while max_ip_selected != "true" or type_all_selected != "true":
        if max_ip_selected != "true" and type_all_selected != "true":
            print(1)
            button_500 = driver.find_element(
                By.XPATH,
                "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[1]/option[6]",
            )

            button_500.click()

            button_500 = driver.find_element(
                By.XPATH,
                "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[1]/option[6]",
            )

            max_ip_selected = button_500.get_attribute("selected")

            button_type_all = driver.find_element(
                By.XPATH,
                "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[6]/option[1]",
            )
            button_type_all.click()

            button_type_all = driver.find_element(
                By.XPATH,
                "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[6]/option[1]",
            )

            type_all_selected = button_type_all.get_attribute("selected")
        else:
            if max_ip_selected != "true" and type_all_selected == "true":
                print(2)
                button_500 = driver.find_element(
                    By.XPATH,
                    "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[1]/option[6]",
                )

                button_500.click()

                button_500 = driver.find_element(
                    By.XPATH,
                    "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[1]/option[6]",
                )

                max_ip_selected = button_500.get_attribute("selected")

                button_type_all = driver.find_element(
                    By.XPATH,
                    "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[6]/option[1]",
                )

                type_all_selected = button_type_all.get_attribute("selected")

            else:
                print(3)
                button_type_all = driver.find_element(
                    By.XPATH,
                    "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[6]/option[1]",
                )
                button_type_all.click()

                button_type_all = driver.find_element(
                    By.XPATH,
                    "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[6]/option[1]",
                )

                type_all_selected = button_type_all.get_attribute("selected")

                button_500 = driver.find_element(
                    By.XPATH,
                    "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr[1]/td[2]/font/select[1]/option[6]",
                )

                max_ip_selected = button_500.get_attribute("selected")

    button_country = driver.find_element(By.XPATH, '//*[@id="tldc"]')
    a = button_country.text
    print(a)
    s = a.split("\n")
    s1 = s.copy()
    s = s[2:-1]
    ip_in_country = s[country - 2]
    print(ip_in_country)
    ip_in_country = ip_in_country.split("(")
    ip_in_country = ip_in_country[1]
    ip_in_country = ip_in_country[:-1]
    f = open("ip_database.txt", "a")
    f.write(str(s1[country]))
    for string_id in range(4, min(504, int(ip_in_country) + 4)):
        try:
            ip = driver.find_element(
                By.XPATH,
                "/html/body/table[2]/tbody/tr[3]/td/table/tbody/tr["
                + str(string_id)
                + "]/td[1]/font",
            )
            IP.append(ip.text)
            print(string_id, "ip was parsed in country", s1[country], ip.text)
        except BaseException:
            print(string_id, "err")
            break
    f.write(str(IP))
    f.write("\n")
    f.close()
driver.close()
