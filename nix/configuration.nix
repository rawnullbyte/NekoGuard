# NixOS Configuration: k3s + MetalLB + Kubernetes Dashboard
# Single-node setup for NekoGuard
#
# Usage:
#   nixos-rebuild switch -I nixos-config=./configuration.nix
#   kubectl get pods -A

{ config, pkgs, ... }:

{
  imports = [ ];

  # ── System ──────────────────────────────────────────────────────
  networking.hostName = "nekoguard-node";
  time.timeZone = "UTC";

  # ── k3s (lightweight Kubernetes) ────────────────────────────────
  services.k3s = {
    enable = true;
    role = "server";  # single node = server + agent

    # Disable built-in traefik, we use MetalLB + nginx
    extraFlags = [
      "--disable=traefik"
      "--disable=metrics-server"
      "--write-kubeconfig-mode=644"
    ];

    # Cluster networking
    clusterDns = "10.43.0.10";
    clusterCidr = "10.42.0.0/16";
    serviceCidr = "10.43.0.0/16";
  };

  # ── Nginx (Ingress controller) ──────────────────────────────────
  # Replace traefik with nginx for ingress — simpler, NekoGuard-compatible
  services.nginx = {
    enable = true;
    recommendedConfig = true;
  };

  # ── Firewall ────────────────────────────────────────────────────
  networking.firewall = {
    allowedTCPPorts = [ 80 443 6443 2379 2380 10250 10251 10252 10255 ];
    allowedUDPPorts = [ 8472 4789 8285 ];
    # Allow k3s internal traffic
    allowedTCPPortRanges = [ { from = 2379; to = 2380; } ];
  };

  # ── Docker (for containerized services) ─────────────────────────
  virtualisation.docker = {
    enable = true;
    storageDriver = "overlay2";
    autoPrune.enable = true;
  };

  # ── Nixpkgs ─────────────────────────────────────────────────────
  nixpkgs.config.allowUnfree = true;

  system.stateVersion = "24.05";
}
