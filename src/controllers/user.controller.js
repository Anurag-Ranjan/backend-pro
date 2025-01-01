import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = await user.generateAccessToken();
    const refreshToken = await user.generateRefreshToken();
    user.refreshToken = refreshToken;
    user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access tokens"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { fullName, userName, email, password } = req.body;
  if (
    [fullName, userName, email, password].some((field) => field?.trim === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }
  console.log("fields done");
  const doesExist = await User.findOne({
    $or: [{ userName }, { email }],
  });

  if (doesExist) {
    throw new ApiError(409, "Username or email already exists");
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;
  // console.log(coverImageLocalPath);

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar image is required");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar image not uploaded");
  }

  const user = await User.create({
    userName: userName.toLowerCase(),
    email,
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    password,
  });

  const isUserCreated = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!isUserCreated) {
    throw new ApiError(500, "User not registered on the database");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, isUserCreated, "User created Successfully"));
});

const userLogin = asyncHandler(async (req, res) => {
  const { userName, email, password } = req.body;
  // console.log(userName);
  // console.log(email);
  // console.log(password);

  if (!(userName || email)) {
    throw new ApiError(400, "Username or email required");
  }
  if (!password) {
    throw new ApiError(400, "Password must be entered");
  }

  const user = await User.findOne({
    $or: [{ userName }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  const isPassCorrect = await user.isPasswordCorrect(password);
  if (!isPassCorrect) {
    throw new ApiError(401, "Incorrect password entered");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully"
      )
    );
});

const userLogout = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: { refreshToken: undefined },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User successfully logged out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const recievedToken = req.cookies?.refreshToken || req.body.refreshToken;

  if (!recievedToken) {
    throw new ApiError(401, "Unauthorized access");
  }

  try {
    const decodedRecievedToken = jwt.verify(
      recievedToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const tokenUser = await User.findById(decodedRecievedToken?._id);

    if (!tokenUser) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (recievedToken !== tokenUser?.refreshToken) {
      throw new ApiError(401, "Refresh token has expired");
    }

    const options = {
      httpOnly: true,
      secure: true,
    };

    const tokens = await generateAccessAndRefreshTokens(tokenUser._id);

    return res
      .status(201)
      .cookie("accessToken", tokens.accessToken, options)
      .cookie("refreshToken", tokens.refreshToken, options)
      .json(
        new ApiResponse(
          200,
          {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
          },
          "Access and refresh token have been refreshed successfully"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const foundUser = await User.findById(req.user?._id);

  if (!foundUser) {
    throw new ApiError(401, "Unauthorized request");
  }

  const isCorrect = await foundUser.isPasswordCorrect(currentPassword);

  if (!isCorrect) {
    throw new ApiError(401, "Incorrect password entered");
  }

  foundUser.password = newPassword;
  await foundUser.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password has been updated successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  res.status(200).json(new ApiResponse(200, req.user, "Current user fetched"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, userName } = req.body;
  if (!fullName || !userName) {
    throw new ApiError(400, "At least one update field required");
  }

  try {
    const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          fullName,
          userName,
        },
      },
      {
        new: true,
      }
    ).select("-password -refreshToken");

    return res
      .status(201)
      .json(new ApiResponse(200, user, "Fields updated successfully"));
  } catch (error) {
    throw new ApiError(500, error?.message || "Cannot Update User");
  }
});

const updateAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path;
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file missing");
  }
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  if (!avatar?.url) {
    throw new ApiError(500, "Could not upload file");
  }
  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: { avatar: avatar.url }, //yahaan galti hui thi aapse
    },
    {
      new: true,
    }
  ).select("-password -refreshToken");

  return res
    .status(201)
    .json(new ApiResponse(200, user, "Avatar image updated successfully"));
});

const updateCoverImg = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path;
  if (!coverImageLocalPath) {
    throw new ApiError(400, "Cover image file missing");
  }
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);
  if (!coverImage?.url) {
    throw new ApiError(500, "Could not upload file");
  }
  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: { coverImage: coverImage.url }, //yahaan galti hui thi aapse
    },
    {
      new: true,
    }
  ).select("-password -refreshToken");

  return res
    .status(201)
    .json(new ApiResponse(200, user, "Cover image updated successfully"));
});

const selectUserChannel = asyncHandler(async (req, res) => {
  const { userName } = req.params;

  if (!userName.trim()) {
    throw new ApiError(400, "Username not recieved");
  }

  const channel = await User.aggregate([
    {
      $match: { userName: userName },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers",
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo",
      },
    },
    {
      $addFields: {
        subscribersCount: {
          $size: "$subscribers",
        },
        subscribedCount: {
          $size: "$subscribedTo",
        },
        isSubscribed: {
          $cond: {
            if: { $in: [req.user?._id, "$subscribers.subscriber"] },
            then: true,
            else: false,
          },
        },
      },
    },
    {
      $project: {
        userName: 1,
        fullName: 1,
        avatar: 1,
        coverImage: 1,
        email: 1,
        subscribersCount: 1,
        subscribedCount: 1,
        isSubscribed: 1,
      },
    },
  ]);

  if (!channel?.length) {
    throw new ApiError(404, "Channel does not exist");
  }

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        channel[0],
        "Channel details have been fetched successfully"
      )
    );
});

export {
  registerUser,
  userLogin,
  userLogout,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateAvatar,
  updateCoverImg,
  selectUserChannel,
};
