# Welcome to Proton-Minerva

This is a simple script that allows you to use Proton VPN as a proxy for Minerva-Archive project!
This is a FORK of the original worker script.
This was painful to re-write in some places, so please give credit.
**YOU MUST HAVE A PROTON VPN SUBSCRIPTION TO USE THIS SCRIPT!**
To obtain your proton credentials follow this guide:
1. Download the Proton VPN Extension for Chrome
2. Login.
3. Right click on the extension and click "Inspect"
4. Click Extension Storage then Click inside of it and click Local
5. get your uid and access token from the bex-session key.

my personal command:

python minerva_requests.py run --concurrency 128 --batch-size 256 --socket-connections 128 --proxy proton --proton-429-timeout --upload-from-ram --ram-max-size 8GB

If i keep getting rate limited I use:

python minerva_requests.py run --concurrency 128 --batch-size 256 --socket-connections 128 --proxy proton --proton-429-timeout --upload-from-ram --ram-max-size 8GB --socket-distinct-ips

you might prefer:

python minerva_requests.py run --concurrency 128 --batch-size 256 --socket-connections 128 --proxy proton --proton-429-timeout --upload-from-ram --ram-max-size 1GB

or:
python minerva_requests.py run --concurrency 16 --batch-size 32 --socket-connections 128 --proxy proton --proton-429-timeout

if you're suffering from the big 26 RAM shortage.
