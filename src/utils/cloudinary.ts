import { v2 as cloudinary } from "cloudinary";
import fs from "fs";
import dotenv from "dotenv";

dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME!,
    api_key: process.env.CLOUDINARY_API_KEY!,
    api_secret: process.env.CLOUDINARY_API_KEY_SECRET!,
});

export const uploadOnCloudinary = async (
    localFilePath?: string
): Promise<string | null> => {
    try {
        if (!localFilePath) return null;

        const result = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "image",
            folder: "screenshots", // folder for website screenshots
        });

        console.log("Screenshot uploaded successfully to Cloudinary", result.secure_url);
        // delete local file after successful upload
        fs.unlinkSync(localFilePath);

        return result.secure_url;
    } catch (error) {
        console.error("Cloudinary upload error:", error);
        // delete local file if upload fails
        if (localFilePath && fs.existsSync(localFilePath)) {
            fs.unlinkSync(localFilePath);
        }
        throw error; // let controller handle error
    }
};
