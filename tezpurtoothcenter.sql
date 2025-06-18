-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jun 18, 2025 at 03:51 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `tezpurtoothcenter`
--

-- --------------------------------------------------------

--
-- Table structure for table `reports`
--

CREATE TABLE `reports` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `image_path` varchar(255) NOT NULL,
  `detection_result` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `reports`
--

INSERT INTO `reports` (`id`, `user_id`, `image_path`, `detection_result`, `created_at`) VALUES
(1, 27, 'static/results\\27\\IMG_2349_JPG.rf.1d3909a2349e118203944d7166f2a084.jpg', '[{\'label\': \'Tooth Cavity\', \'confidence\': 0.87}, {\'label\': \'Impacted Tooth\', \'confidence\': 0.76}]', '2025-06-18 18:59:09'),
(2, 27, 'static/results\\27\\IMG_2349_JPG.rf.1d3909a2349e118203944d7166f2a084.jpg', '[{\'label\': \'Tooth Cavity\', \'confidence\': 0.87}, {\'label\': \'Impacted Tooth\', \'confidence\': 0.76}]', '2025-06-18 19:00:46'),
(3, 27, 'static/results\\27\\IMG_2349_JPG.rf.25cb14000554008de893646e2ca89ca3.jpg', '[{\'label\': \'Tooth Cavity\', \'confidence\': 0.87}, {\'label\': \'Impacted Tooth\', \'confidence\': 0.76}]', '2025-06-18 19:02:03'),
(4, 27, 'static/results\\27\\IMG_2349_JPG.rf.25cb14000554008de893646e2ca89ca3.jpg', '[{\'label\': \'Tooth Cavity\', \'confidence\': 0.87}, {\'label\': \'Impacted Tooth\', \'confidence\': 0.76}]', '2025-06-18 19:09:18'),
(5, 27, 'static/results\\27\\IMG_20250515_121718.jpg', '[{\'label\': \'Tooth Cavity\', \'confidence\': 0.87}, {\'label\': \'Impacted Tooth\', \'confidence\': 0.76}]', '2025-06-18 19:18:42'),
(6, 30, 'static/results\\30\\IMG_20250407_090259.jpg', '[{\'label\': \'Tooth Cavity\', \'confidence\': 0.87}, {\'label\': \'Impacted Tooth\', \'confidence\': 0.76}]', '2025-06-18 19:20:12');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `email` varchar(200) NOT NULL,
  `password` varchar(100) NOT NULL,
  `verified` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `password`, `verified`) VALUES
(1, 'Prasurya Kakati', 'pk@gmail.com', '$2b$12$PSAS69juTYiZkx6GnGkpUei9D0aXClaKqyIEIY7AuDY8bvinsBZGa', 0),
(27, 'Alakananda Kakati', 'gptdrona@gmail.com', '$2b$12$XQyjuSi0ziGfg6TFzel7SeHH0xsgp.iGAT.iS5L4y2jr8meQV27vC', 1),
(30, 'Prasurya Kakati', 'politechblock801451@gmail.com', '$2b$12$TQgrsysRdrCX37BdzPCb2.36ILnjcQCslyhjVh.JPrYl8N4DvypKe', 1);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `reports`
--
ALTER TABLE `reports`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `reports`
--
ALTER TABLE `reports`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=31;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `reports`
--
ALTER TABLE `reports`
  ADD CONSTRAINT `reports_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
