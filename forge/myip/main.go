// Copyright (c) 2025 honeok <honeok@duck.com>

package main

import (
    "github.com/gin-gonic/gin"
    "log"
    "net"
    "net/http"
    "strings"
)

func main() {
    gin.SetMode(gin.ReleaseMode)

    r := gin.New()
    r.Use(gin.Recovery())
    r.Use(minimalLogger())

    r.GET("/", func(c *gin.Context) {
        clientIP := getClientIP(c)

        c.String(http.StatusOK, clientIP)
    })

    if err := r.Run(":8080"); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}

func minimalLogger() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()

        log.Printf("[GIN] %s %s %d %s", c.Request.Method, c.Request.URL.Path, c.Writer.Status(), getClientIP(c))
    }
}

func getClientIP(c *gin.Context) string {
    forwarded := c.GetHeader("X-Forwarded-For")
    if forwarded != "" {
        ips := strings.Split(forwarded, ",")
        for _, ip := range ips {
            ip = strings.TrimSpace(ip)
            if isValidIP(ip) {
                return ip
            }
        }
    }

    return c.ClientIP()
}

func isValidIP(ip string) bool {
    if ip == "" {
        return false
    }
    return net.ParseIP(ip) != nil
}