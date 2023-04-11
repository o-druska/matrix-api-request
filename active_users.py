import requests as rq

def main():
    username = "oskar.d"
    domain = "inm7.de"

    print(username)
    print(domain)

    headers = {
        "Authorization": "<censored>" # You have to provide your own accestoken (Im not gonna push my own token here hehe)
    }
    print(headers)

    tobias_profile = rq.get(url=f"https://inm7.modular.im/_matrix/client/v3/profile/@tobias:inm7.de", headers=headers)
    print(tobias_profile)
    print(tobias_profile.json())

    oskar_presence_status = rq.get(
        url = f"https://inm7.modular.im/_matrix/client/v3/presence/@{username}:{domain}/status",
        headers = headers
    )
    print(oskar_presence_status)
    print(oskar_presence_status.json())


if __name__ == "__main__":
    main()
