import { Request, Response } from "express";
const express = require("express");
const axios = require("axios");
const router = express.Router();

// Fetch HackerNews top stories
const fetchStories = async (req: Request, res: Response, endpoint: string) => {
  const limit = parseInt(req.query.limit as string) || 30;
  const offset = parseInt(req.query.offset as string) || 0;

  try {
    // Fetch the list of story IDs
    const { data: storyIds } = await axios.get(
      `https://hacker-news.firebaseio.com/v0/${endpoint}.json`
    );

    // Fetch the details for the stories based on offset and limit
    const storyPromises = storyIds
      .slice(offset, offset + limit)
      .map(async (id: number) => {
        const { data: story } = await axios.get(
          `https://hacker-news.firebaseio.com/v0/item/${id}.json`
        );
        return story;
      });

    const stories = await Promise.all(storyPromises);

    res.status(200).json(stories);
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve stories." });
  }
};
// Fetch HackerNews top stories
router.get("/topStories", async (req: Request, res: Response) => {
  await fetchStories(req, res, "topstories");
});

// Fetch HackerNews new stories
router.get("/newStories", async (req: Request, res: Response) => {
  await fetchStories(req, res, "newstories");
});

// Fetch HackerNews ask stories
router.get("/askStories", async (req: Request, res: Response) => {
  await fetchStories(req, res, "askstories");
});

// Fetch HackerNews show stories
router.get("/showStories", async (req: Request, res: Response) => {
  await fetchStories(req, res, "showstories");
});

// Fetch HackerNews job stories
router.get("/jobStories", async (req: Request, res: Response) => {
  await fetchStories(req, res, "jobstories");
});

// Fetch comments for a story
router.get("/comments/:storyId", async (req: Request, res: Response) => {
  try {
    const { storyId } = req.params;

    // Fetch the story using axios
    const { data: story } = await axios.get(
      `https://hacker-news.firebaseio.com/v0/item/${storyId}.json`
    );

    const commentIds = story.kids;
    if (!commentIds) {
      res.status(200).json([]);
      return;
    }

    // Fetch comments for the story
    const commentPromises = commentIds.map(async (id: number) => {
      const { data: comment } = await axios.get(
        `https://hacker-news.firebaseio.com/v0/item/${id}.json`
      );
      return comment;
    });

    const comments = await Promise.all(commentPromises);
    res.status(200).json(comments);
  } catch (error) {
    res
      .status(500)
      .json({ error: "Failed to retrieve comments for the story." });
  }
});

// Fetch kids (sub-comments) for each comment recursively
router.get("/kids/:commentId", async (req: Request, res: Response) => {
  try {
    const { commentId } = req.params;

    const fetchCommentAndKids = async (commentId: number) => {
      // Fetch the comment using axios
      const { data: comment } = await axios.get(
        `https://hacker-news.firebaseio.com/v0/item/${commentId}.json`
      );

      if (comment.kids && comment.kids.length > 0) {
        // Recursively fetch kids of the comment
        const kidsPromises = comment.kids.map((kidId: number) =>
          fetchCommentAndKids(kidId)
        );
        comment.kids = await Promise.all(kidsPromises);
      }

      return comment;
    };

    const commentWithKids = await fetchCommentAndKids(Number(commentId));
    res.status(200).json(commentWithKids);
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve sub-comments" });
  }
});

// Fetch all public user profiles by ID
router.get("/users/:userId", async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;

    // Fetch user profile using axios
    const { data: user } = await axios.get(
      `https://hacker-news.firebaseio.com/v0/user/${userId}.json`
    );
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve user profiles." });
  }
});

// Search option using Algolia
router.get("/search", async (req: Request, res: Response) => {
  try {
    const { q } = req.query;
    const { data } = await axios.get(
      `https://hn.algolia.com/api/v1/search?hitsPerPage=50&query=${q}`
    );
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: "Failed to search." });
  }
});

export default router;
