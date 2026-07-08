package com.nmapscanner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Controller
public class NmapController {
    
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final Map<String, SseEmitter> emitters = new ConcurrentHashMap<>();
    private final Map<String, String> scanStatus = new ConcurrentHashMap<>();
    private final Map<String, List<String>> scanResults = new ConcurrentHashMap<>();
    private final Map<String, Long> scanStartTime = new ConcurrentHashMap<>();
    
    private String detectedNmapPath = null;
    
    private String getNmapPath() {
        if (detectedNmapPath != null) {
            return detectedNmapPath;
        }
        
        String[] paths = {
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "nmap",
            "C:\\Program Files\\Nmap\\nmap.exe",
            "C:\\Program Files (x86)\\Nmap\\nmap.exe"
        };
        
        for (String path : paths) {
            try {
                ProcessBuilder pb = new ProcessBuilder(path, "--version");
                Process p = pb.start();
                if (p.waitFor(2, TimeUnit.SECONDS)) {
                    detectedNmapPath = path;
                    System.out.println("✅ Found Nmap at: " + path);
                    return path;
                }
            } catch (Exception e) {
                // Continue checking
            }
        }
        
        detectedNmapPath = "nmap";
        System.out.println("⚠️ Nmap not found. Using default: nmap");
        return detectedNmapPath;
    }
    
    @GetMapping("/")
    public String index(Model model) {
        return "index";
    }
    
    @PostMapping("/scan")
    @ResponseBody
    public Map<String, Object> startScan(@RequestParam String target,
                                         @RequestParam String scanType,
                                         @RequestParam(required = false) String ports,
                                         @RequestParam(required = false) String options) {
        Map<String, Object> response = new HashMap<>();
        String scanId = UUID.randomUUID().toString();
        
        String command = buildCommand(target, scanType, ports, options);
        
        scanStatus.put(scanId, "running");
        scanResults.put(scanId, new ArrayList<>());
        scanStartTime.put(scanId, System.currentTimeMillis());
        
        // Use final variables for lambda
        final String finalScanId = scanId;
        final String finalCommand = command;
        
        executor.submit(() -> {
            // Use arrays as containers for mutable references (FIX for lambda)
            final Process[] processHolder = new Process[1];
            final Thread[] outputReaderHolder = new Thread[1];
            
            try {
                System.out.println("🔍 Starting scan: " + finalScanId + " for target: " + target);
                
                ProcessBuilder pb = new ProcessBuilder(finalCommand.split(" "));
                pb.redirectErrorStream(true);
                Process process = pb.start();
                processHolder[0] = process;
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                
                // Use final reference for the scanner
                final BufferedReader finalReader = reader;
                
                Thread outputReader = new Thread(() -> {
                    try {
                        String line;
                        while ((line = finalReader.readLine()) != null) {
                            final String finalLine = line;
                            scanResults.get(finalScanId).add(finalLine);
                            sendUpdate(finalScanId, finalLine);
                        }
                    } catch (IOException e) {
                        // Reader closed
                    }
                });
                outputReader.start();
                outputReaderHolder[0] = outputReader;
                
                // ═══════════════════════════════════════════════════
                // ✅ 5-MINUTE TIMEOUT
                // ═══════════════════════════════════════════════════
                boolean finished = process.waitFor(5, java.util.concurrent.TimeUnit.MINUTES);
                
                if (!finished) {
                    process.destroy();
                    if (outputReaderHolder[0] != null) {
                        outputReaderHolder[0].interrupt();
                    }
                    scanStatus.put(finalScanId, "timeout");
                    sendUpdate(finalScanId, "ERROR: Scan timed out after 5 minutes");
                    sendUpdate(finalScanId, "SCAN_COMPLETE:timeout");
                    System.out.println("⏰ Scan timed out after 5 minutes for: " + finalScanId);
                } else {
                    int exitCode = process.exitValue();
                    scanStatus.put(finalScanId, "complete");
                    sendUpdate(finalScanId, "SCAN_COMPLETE:" + exitCode);
                    System.out.println("✅ Scan completed with exit code: " + exitCode + " for: " + finalScanId);
                }
                
                // Clean up after 10 minutes
                executor.submit(() -> {
                    try {
                        Thread.sleep(600000);
                        scanResults.remove(finalScanId);
                        scanStatus.remove(finalScanId);
                        scanStartTime.remove(finalScanId);
                        System.out.println("🧹 Cleaned up scan: " + finalScanId);
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                });
                
            } catch (Exception e) {
                scanStatus.put(finalScanId, "error");
                String errorMsg = e.getMessage() != null ? e.getMessage() : "Unknown error";
                sendUpdate(finalScanId, "ERROR: " + errorMsg);
                sendUpdate(finalScanId, "SCAN_COMPLETE:error");
                System.err.println("❌ Error in scan " + finalScanId + ": " + errorMsg);
                e.printStackTrace();
                
                // Clean up on error
                if (processHolder[0] != null) {
                    processHolder[0].destroy();
                }
                if (outputReaderHolder[0] != null) {
                    outputReaderHolder[0].interrupt();
                }
            } finally {
                if (processHolder[0] != null && processHolder[0].isAlive()) {
                    processHolder[0].destroy();
                }
            }
        });
        
        response.put("scanId", scanId);
        response.put("message", "Scan started successfully");
        return response;
    }
    
    @GetMapping("/stream/{scanId}")
    public SseEmitter stream(@PathVariable String scanId) {
        SseEmitter emitter = new SseEmitter(600000L);
        
        emitters.put(scanId, emitter);
        
        List<String> existingResults = scanResults.get(scanId);
        if (existingResults != null && !existingResults.isEmpty()) {
            try {
                for (String line : existingResults) {
                    emitter.send(line);
                }
            } catch (Exception e) {
                // Ignore
            }
        }
        
        emitter.onCompletion(() -> {
            emitters.remove(scanId);
            System.out.println("✅ Stream completed for scan: " + scanId);
        });
        
        emitter.onTimeout(() -> {
            emitters.remove(scanId);
            System.out.println("⏰ Stream timed out for scan: " + scanId);
        });
        
        emitter.onError((e) -> {
            emitters.remove(scanId);
            System.out.println("❌ Stream error for scan: " + scanId + " - " + e.getMessage());
        });
        
        return emitter;
    }
    
    @GetMapping("/status/{scanId}")
    @ResponseBody
    public Map<String, Object> getStatus(@PathVariable String scanId) {
        Map<String, Object> response = new HashMap<>();
        String status = scanStatus.getOrDefault(scanId, "not_found");
        response.put("scanId", scanId);
        response.put("status", status);
        response.put("results", scanResults.getOrDefault(scanId, new ArrayList<>()));
        
        Long startTime = scanStartTime.get(scanId);
        if (startTime != null) {
            long elapsed = System.currentTimeMillis() - startTime;
            response.put("elapsedSeconds", elapsed / 1000);
        }
        
        return response;
    }
    
    @GetMapping("/health")
    @ResponseBody
    public Map<String, String> health() {
        Map<String, String> status = new HashMap<>();
        status.put("status", "UP");
        status.put("nmap", checkNmap());
        status.put("timestamp", new Date().toString());
        return status;
    }
    
    private String checkNmap() {
        String nmapPath = getNmapPath();
        try {
            ProcessBuilder pb = new ProcessBuilder(nmapPath, "--version");
            Process p = pb.start();
            if (p.waitFor(2, TimeUnit.SECONDS)) {
                return "OK - " + nmapPath;
            }
            return "FAILED - Nmap not responding";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    private void sendUpdate(String scanId, String data) {
        SseEmitter emitter = emitters.get(scanId);
        if (emitter != null) {
            try {
                emitter.send(data);
            } catch (Exception e) {
                emitters.remove(scanId);
                System.out.println("❌ Error sending update to " + scanId + ": " + e.getMessage());
            }
        }
    }
    
    private String buildCommand(String target, String scanType, String ports, String options) {
        String nmapPath = getNmapPath();
        System.out.println("🔍 Using Nmap path: " + nmapPath);
        
        StringBuilder cmd = new StringBuilder(nmapPath);
        
        switch (scanType) {
            case "quick":
                if (ports != null && !ports.isEmpty()) {
                    cmd.append(" -p ").append(ports);
                } else {
                    cmd.append(" -p 22,80,443,631,3306,8080");
                }
                break;
            case "full":
                cmd.append(" -p-");
                break;
            case "service":
                cmd.append(" -sV");
                break;
            case "os":
                cmd.append(" -O");
                break;
            case "network":
                cmd.append(" -sn");
                break;
            default:
                cmd.append(" -p 22,80,443");
        }
        
        if (options != null && !options.isEmpty()) {
            cmd.append(" ").append(options);
        }
        
        cmd.append(" ").append(target);
        
        System.out.println("📡 Running command: " + cmd.toString());
        return cmd.toString();
    }
}