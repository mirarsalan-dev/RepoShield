"use client";

import React, { useEffect, useState, useCallback } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence, useReducedMotion } from "framer-motion";
import {
  popupModalVariants,
  reducedModalVariants,
  backdropVariants,
  reducedBackdropVariants,
} from "./motion-presets";

export interface AnimatedDialogProps {
  isOpen: boolean;
  onClose: () => void;
  children: React.ReactNode;
  className?: string;
  overlayClassName?: string;
  closeOnEscape?: boolean;
  closeOnClickOutside?: boolean;
  enableDragDismiss?: boolean;
  dragDismissThreshold?: number;
  position?: "center" | "top";
  ariaLabel?: string;
}

export function AnimatedDialog({
  isOpen,
  onClose,
  children,
  className = "",
  overlayClassName = "",
  closeOnEscape = true,
  closeOnClickOutside = true,
  enableDragDismiss = false,
  dragDismissThreshold = 100,
  position = "center",
  ariaLabel,
}: AnimatedDialogProps) {
  const [mounted, setMounted] = useState(false);
  const shouldReduceMotion = useReducedMotion();

  useEffect(() => {
    setMounted(true);
  }, []);

  // Escape key handler
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (closeOnEscape && e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    },
    [closeOnEscape, onClose]
  );

  useEffect(() => {
    if (isOpen) {
      document.addEventListener("keydown", handleKeyDown);
      // Prevent background scrolling while modal is open
      const originalOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
      return () => {
        document.removeEventListener("keydown", handleKeyDown);
        document.body.style.overflow = originalOverflow;
      };
    }
  }, [isOpen, handleKeyDown]);

  const modalVariants = shouldReduceMotion ? reducedModalVariants : popupModalVariants;
  const overlayVariants = shouldReduceMotion ? reducedBackdropVariants : backdropVariants;

  const positionClasses =
    position === "top"
      ? "items-start pt-16 md:pt-20 justify-center p-4"
      : "items-center justify-center p-4";

  if (!mounted) {
    return null;
  }

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <motion.div
          key="dialog-overlay"
          role="dialog"
          aria-modal="true"
          aria-label={ariaLabel}
          variants={overlayVariants}
          initial="hidden"
          animate="visible"
          exit="exit"
          onClick={() => {
            if (closeOnClickOutside) onClose();
          }}
          className={`fixed inset-0 z-[100] flex ${positionClasses} bg-black/60 backdrop-blur-[6px] select-none ${overlayClassName}`}
        >
          <motion.div
            key="dialog-surface"
            variants={modalVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            drag={enableDragDismiss ? "y" : false}
            dragConstraints={{ top: 0, bottom: 0 }}
            dragElastic={{ top: 0.05, bottom: 0.5 }}
            onDragEnd={(_, info) => {
              if (
                enableDragDismiss &&
                (info.offset.y > dragDismissThreshold || info.velocity.y > 450)
              ) {
                onClose();
              }
            }}
            onClick={(e) => e.stopPropagation()}
            className={`relative max-w-full select-text macos-window ${className}`}
          >
            {enableDragDismiss && (
              <div className="w-full flex justify-center pt-2 pb-1 cursor-grab active:cursor-grabbing">
                <div className="w-9 h-1 rounded-full bg-[var(--border-strong)] opacity-60" />
              </div>
            )}
            {children}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body
  );
}
