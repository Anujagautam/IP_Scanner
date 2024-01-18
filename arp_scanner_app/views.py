from django.shortcuts import render
from .models import ScanResult
from scapy.layers.l2 import ARP, Ether, srp


def scan(ip):
    arp_request = ARP(pdst=ip)

    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    results = []

    for element in answered_list:
        result_dict = {"ip": element[1].psrc}
        results.append(result_dict)

    return results


def main(request):
    scan_results = []
    non_reachable_ips = []

    reachable_ips = []

    if request.method == 'POST':
        start_ip = request.POST.get('start_ip')
        end_ip = request.POST.get('end_ip')

        all_ips = [f"{i}.{j}.{k}.{l}" for i in range(int(start_ip.split('.')[0]), int(end_ip.split('.')[0]) + 1)
                   for j in range(int(start_ip.split('.')[1]), int(end_ip.split('.')[1]) + 1)
                   for k in range(int(start_ip.split('.')[2]), int(end_ip.split('.')[2]) + 1)
                   for l in range(int(start_ip.split('.')[3]), int(end_ip.split('.')[3]) + 1)]

        scan_results = scan(all_ips)

        reachable_ips = [result["ip"] for result in scan_results]
        non_reachable_ips = list(set(all_ips) - set(reachable_ips))

        reachable_ips.sort()
        non_reachable_ips.sort()

        for ip in reachable_ips:
            ScanResult.objects.create(ip=ip)

    return render(request, 'scan.html', {'scan_results': reachable_ips, 'non_reachable_ips': non_reachable_ips})
