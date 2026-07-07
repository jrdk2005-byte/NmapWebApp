package com.nmapscanner;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

@Controller
public class NmapController {
    
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final Map<String, SseEmitter> emitters = new ConcurrentHashMap<>();
    
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
        
        // Build Nmap command
        String command = buildCommand(target, scanType, ports, options);
        
        // Start scan in background
        executor.submit(() -> {
            try {
                ProcessBuilder pb = new ProcessBuilder(command.split(" "));
                pb.redirectErrorStream(true);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                
                String line;
                while ((line = reader.readLine()) != null) {
                    sendUpdate(scanId, line);
                }
                
                int exitCode = process.waitFor();
                sendUpdate(scanId, "SCAN_COMPLETE:" + exitCode);
                
            } catch (Exception e) {
                sendUpdate(scanId, "ERROR: " + e.getMessage());
            }
        });
        
        response.put("scanId", scanId);
        response.put("message", "Scan started");
        return response;
    }
    
    @GetMapping("/stream/{scanId}")
    public SseEmitter stream(@PathVariable String scanId) {
        SseEmitter emitter = new SseEmitter(300000L); // 5 minutes timeout
        emitters.put(scanId, emitter);
        
        emitter.onCompletion(() -> emitters.remove(scanId));
        emitter.onTimeout(() -> emitters.remove(scanId));
        
        return emitter;
    }
    
    private void sendUpdate(String scanId, String data) {
        SseEmitter emitter = emitters.get(scanId);
        if (emitter != null) {
            try {
                emitter.send(data);
            } catch (Exception e) {
                emitters.remove(scanId);
            }
        }
    }
    
    private String buildCommand(String target, String scanType, String ports, String options) {
        StringBuilder cmd = new StringBuilder("C:\\Program Files (x86)\\Nmap\\nmap.exe");
        
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
        }
        
        if (options != null && !options.isEmpty()) {
            cmd.append(" ").append(options);
        }
        
        cmd.append(" ").append(target);
        return cmd.toString();
    }
}