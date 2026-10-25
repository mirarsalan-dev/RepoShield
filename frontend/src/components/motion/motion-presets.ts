import { Variants, Transition } from "framer-motion";

/**
 * RepoShield macOS-Inspired Motion Presets
 * Grounded in Apple HIG and Linear/Raycast design principles.
 */

// Controlled macOS spring settings
export const macOSSpring: Transition = {
  type: "spring",
  stiffness: 340,
  damping: 28,
  mass: 0.8,
};

// Gentle spring for micro-interactions
export const gentleSpring: Transition = {
  type: "spring",
  stiffness: 400,
  damping: 32,
  mass: 0.6,
};

// macOS standard bezier ease
export const macOSEase = [0.22, 1, 0.36, 1] as const;
export const macOSExitEase = [0.4, 0, 1, 1] as const;

/**
 * 1. Motion-Blur Page Transitions (Top-to-Down Cascade)
 * Incoming: starts at y: -14, blur(4px), scale: 0.995, opacity: 0 -> drops down to y: 0 in 250ms
 * Outgoing: exits downward to y: 10, blur(3px), scale: 0.995, opacity: 0 in 160ms
 */
export const pageMotionVariants: Variants = {
  initial: {
    opacity: 0,
    filter: "blur(4px)",
    y: -14,
    scale: 0.995,
  },
  animate: {
    opacity: 1,
    filter: "blur(0px)",
    y: 0,
    scale: 1,
    transition: {
      duration: 0.25,
      ease: macOSEase,
    },
  },
  exit: {
    opacity: 0,
    filter: "blur(3px)",
    y: 10,
    scale: 0.995,
    transition: {
      duration: 0.16,
      ease: macOSExitEase,
    },
  },
};

// Reduced motion fallback for page transitions
export const reducedPageMotionVariants: Variants = {
  initial: { opacity: 0 },
  animate: { opacity: 1, transition: { duration: 0.12 } },
  exit: { opacity: 0, transition: { duration: 0.08 } },
};

/**
 * 2. Popup Entrance & Exit (Spring-based Drag Down & Lift Away)
 * Entrance: Starts y: -24px, scale: 0.96, blur(4px) -> settles with spring
 * Exit: Lifts up to y: -14px, scale: 0.98, blur(2px), opacity: 0 in 160ms
 */
export const popupModalVariants: Variants = {
  hidden: {
    opacity: 0,
    y: -24,
    scale: 0.96,
    filter: "blur(4px)",
  },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    filter: "blur(0px)",
    transition: macOSSpring,
  },
  exit: {
    opacity: 0,
    y: -14,
    scale: 0.98,
    filter: "blur(2px)",
    transition: {
      duration: 0.16,
      ease: macOSExitEase,
    },
  },
};

export const reducedModalVariants: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.12 } },
  exit: { opacity: 0, transition: { duration: 0.08 } },
};

/**
 * 3. Modal Backdrop Overlay
 * Synchronized fade and subtle backdrop blur
 */
export const backdropVariants: Variants = {
  hidden: {
    opacity: 0,
    backdropFilter: "blur(0px)",
  },
  visible: {
    opacity: 1,
    backdropFilter: "blur(6px)",
    transition: {
      duration: 0.2,
      ease: "easeOut",
    },
  },
  exit: {
    opacity: 0,
    backdropFilter: "blur(0px)",
    transition: {
      duration: 0.16,
      ease: "easeIn",
    },
  },
};

export const reducedBackdropVariants: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.1 } },
  exit: { opacity: 0, transition: { duration: 0.08 } },
};
