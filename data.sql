-- MySQL dump 10.13  Distrib 8.0.29, for Win64 (x86_64)
--
-- Host: localhost    Database: event
-- ------------------------------------------------------
-- Server version	8.0.29

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `attendee`
--

DROP TABLE IF EXISTS `attendee`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `attendee` (
  `at_id` int unsigned NOT NULL AUTO_INCREMENT,
  `at_name` varchar(50) NOT NULL,
  `phone_num` bigint DEFAULT NULL,
  `email` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`at_id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `attendee`
--

LOCK TABLES `attendee` WRITE;
/*!40000 ALTER TABLE `attendee` DISABLE KEYS */;
INSERT INTO `attendee` VALUES (1,'taneem',9632145685,'tan@outlook.com'),(2,'ayesha',4589632145,'ay@gmail.com'),(3,'sam',NULL,NULL),(4,'jyotshna',NULL,NULL),(5,'shareef',NULL,NULL),(6,'rudhira',NULL,NULL),(7,'bat',NULL,NULL),(8,'rat',NULL,NULL),(9,'cat',NULL,NULL);
/*!40000 ALTER TABLE `attendee` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `event`
--

DROP TABLE IF EXISTS `event`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `event` (
  `ev_id` int unsigned NOT NULL,
  `ev_name` varchar(50) NOT NULL,
  `ev_date` date DEFAULT NULL,
  `ev_location` varchar(50) DEFAULT NULL,
  `org_id` int unsigned DEFAULT NULL,
  PRIMARY KEY (`ev_id`),
  KEY `org_id` (`org_id`),
  CONSTRAINT `event_ibfk_1` FOREIGN KEY (`org_id`) REFERENCES `organizer` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `event`
--

LOCK TABLES `event` WRITE;
/*!40000 ALTER TABLE `event` DISABLE KEYS */;
INSERT INTO `event` VALUES (101,'Food Carnival','2024-04-10','Vijayawada',1),(102,'Tech Innovators Conferencel','2014-04-14','Hyderabad',2),(103,'Charity Run Marathon','1914-04-14','Guntur',1),(104,'Startup Pitch Fest','2204-12-10','Vizag',3);
/*!40000 ALTER TABLE `event` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `event_sponsors`
--

DROP TABLE IF EXISTS `event_sponsors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_sponsors` (
  `ev_id` int unsigned DEFAULT NULL,
  `s_id` int unsigned DEFAULT NULL,
  KEY `ev_id` (`ev_id`),
  KEY `s_id` (`s_id`),
  CONSTRAINT `event_sponsors_ibfk_1` FOREIGN KEY (`ev_id`) REFERENCES `event` (`ev_id`),
  CONSTRAINT `event_sponsors_ibfk_2` FOREIGN KEY (`s_id`) REFERENCES `sponsor` (`s_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `event_sponsors`
--

LOCK TABLES `event_sponsors` WRITE;
/*!40000 ALTER TABLE `event_sponsors` DISABLE KEYS */;
INSERT INTO `event_sponsors` VALUES (101,1),(101,2),(103,2),(102,2),(104,1),(104,2);
/*!40000 ALTER TABLE `event_sponsors` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `organizer`
--

DROP TABLE IF EXISTS `organizer`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `organizer` (
  `org_id` int unsigned NOT NULL,
  `org_name` varchar(50) NOT NULL DEFAULT 'Taneem',
  `org_num` bigint NOT NULL,
  `email` varchar(50) NOT NULL,
  PRIMARY KEY (`org_id`),
  UNIQUE KEY `org_num` (`org_num`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `organizer`
--

LOCK TABLES `organizer` WRITE;
/*!40000 ALTER TABLE `organizer` DISABLE KEYS */;
INSERT INTO `organizer` VALUES (1,'Afsha',7412589632,'afs@gmail.com'),(2,'Taufeer',36985214755,'tauf@gmail.com'),(3,'Ayaan',8521469573,'ayaan@yahoo.com'),(4,'Taneem',9685753698,'kow@awesome.com'),(5,'jyo',1235647895,'jonnala@klu.in');
/*!40000 ALTER TABLE `organizer` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sponsor`
--

DROP TABLE IF EXISTS `sponsor`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sponsor` (
  `s_id` int unsigned NOT NULL AUTO_INCREMENT,
  `s_name` varchar(30) NOT NULL,
  `contact_num` bigint DEFAULT NULL,
  `s_amt` int NOT NULL,
  PRIMARY KEY (`s_id`),
  UNIQUE KEY `contact_num` (`contact_num`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sponsor`
--

LOCK TABLES `sponsor` WRITE;
/*!40000 ALTER TABLE `sponsor` DISABLE KEYS */;
INSERT INTO `sponsor` VALUES (1,'nasreen',7896545587,7896541),(2,'kareemulla',2365124789,2368745),(3,'babuji',3654236665,4897563);
/*!40000 ALTER TABLE `sponsor` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ticket`
--

DROP TABLE IF EXISTS `ticket`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ticket` (
  `t_id` int unsigned NOT NULL AUTO_INCREMENT,
  `t_type` varchar(30) NOT NULL,
  `price` int unsigned NOT NULL,
  `event_id` int unsigned NOT NULL,
  `atte_id` int unsigned NOT NULL,
  PRIMARY KEY (`event_id`,`atte_id`),
  UNIQUE KEY `t_id` (`t_id`),
  KEY `atte_id` (`atte_id`),
  CONSTRAINT `ticket_ibfk_1` FOREIGN KEY (`event_id`) REFERENCES `event` (`ev_id`),
  CONSTRAINT `ticket_ibfk_2` FOREIGN KEY (`atte_id`) REFERENCES `attendee` (`at_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ticket`
--

LOCK TABLES `ticket` WRITE;
/*!40000 ALTER TABLE `ticket` DISABLE KEYS */;
INSERT INTO `ticket` VALUES (3,'Family Pack',9630,101,3),(2,'Student Pass',500,103,1),(1,'VIP',2500000,103,2),(4,'Group Pass',56321,104,5);
/*!40000 ALTER TABLE `ticket` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-05-06 12:53:54
