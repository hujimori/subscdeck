package main

import (
	"log"
	"os"

	"github.com/Yusuke-Godai/subscdeck/internal/database"
	"github.com/Yusuke-Godai/subscdeck/internal/seeder"
	"github.com/joho/godotenv"
)

func main() {
	// .env.localを優先的に読み込み、なければ.envを読み込む
	err := godotenv.Load(".env.local")
	if err != nil {
		err = godotenv.Load(".env")
		if err != nil {
			log.Println("No .env file found, using environment variables")
		}
	}

	// データベースの初期化
	err = database.InitDB("subscdeck.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// テストユーザーIDを固定で設定
	// main.goで使われているものと同じID
	testUserID := "77448a08-9001-70cf-ba00-98f2b665608b"

	// データ投入の実行
	err = seeder.SeedDevelopmentData(database.GetDB(), testUserID)
	if err != nil {
		log.Fatalf("Failed to seed database: %v", err)
	}

	log.Println("Database seeding completed successfully.")
}