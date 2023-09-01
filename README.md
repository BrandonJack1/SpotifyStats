# Spotify Stats

Video Demo how I provisioned the web app on AWS aswell as a demo of how the web app works: https://youtu.be/AaXeOJQzcKA

I developed a simple user-friendly social media web app named "Spotify Stats." This platform enhances your music experience by seamlessly integrating with you and your friends Spotify accounts. After logging in, you can easily manage your friend list, keeping tabs on their current tracks, recent listens (up to five), as well as their favorite artists and songs. Your own profile offers personalized music insights as well.

The backend, powered by Python with Flask, collaborates with the Spotify API to fetch and refine user data like usernames, top tracks, and listening history. The frontend employs HTML render templates served by Flask which are customized using CSS. The app runs on an AWS EC2 instance, utilizing AWS DynamoDB for data storage. Spotify Stats also uses AWS services like lambda, Secrets Manager, AWS Backup, and VPC.
